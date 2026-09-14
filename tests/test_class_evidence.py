#!/usr/bin/env python3
"""F1 closed codecs for class-provenance.v0 and class-attempt.v0 (#103).

Nonexecuting. No aggregate score. No CLI. No F2/F3/F4.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import corpus_adequacy as ca  # noqa: E402
from test_corpus_adequacy import (  # noqa: E402
    producer_shaped_report,
    producer_shaped_row,
)

PROVENANCE_SCHEMA = "corpus-adequacy.class-provenance.v0"
ATTEMPT_SCHEMA = "corpus-adequacy.class-attempt.v0"
COMMIT_A = "a" * 40
COMMIT_B = "b" * 40
TREE_A = "sha256:" + "1" * 64
TREE_B = "sha256:" + "2" * 64
OBS_A = "sha256:" + "3" * 64
CONTENT_A = "sha256:" + "4" * 64
ENV_BYTES = b"environment-bytes-v0\n"

CLASS_NON_CLAIMS = [
    "No evidence class proves rule completeness, corpus quality, implementation correctness, real-world prevalence, security, conformance, or author independence.",
    "Each denominator is one declared selection and is not a population estimate.",
    "This artifact defines one class only; no aggregate score or overall adequacy exists.",
]

PRESERVED_REPORT_HASHES = {
    "tests/fixtures/publication/valid-tersign/report.v0.json":
        "c65f8a6c6dcc4a56dea31e7fc0de241a8cbbdcf36cd4cf98c220d23a894fe5ae",
    "tests/fixtures/publication/survived-silent/report.v0.json":
        "76cae24c322aff6b1eea39d840e4f1dc38eebc8411c3f8045a07f1b55cae33a8",
    "tests/fixtures/publication/unproved-control/report.v0.json":
        "b583a66d8c0e56fe35f627d6e713528bb476c25a05d53fc9796e2adba7bdddfa",
    "tests/fixtures/publication/void-run-attempt/report.v0.json":
        "a3fe7f1682dc81e6841c14d7017860a12f6396e892704bf518e919af47628889",
    "measurements/tersign-1cc5ea32/report.v0.json":
        "d7c9039da10bd444a4861ef9d9d62565ab7bd4aa29186583335ac8c08dbc7f65",
    "measurements/tersign-0e560c1/report.v0.json":
        "6b8a49ce5f63c2b5a38a6b336a601b5ef7feabe6611c2e44bf5d481702e1f2ee",
}

PINNED_DECLARED_PROVENANCE_SHA256 = (
    "d52f96d11b0c97b5a3ab0c916b47879e8b25890cffb37128e841d16a1853c538"
)
PINNED_COMPLETED_ATTEMPT_SHA256 = (
    "1976be698d204aeb3bcd10a78060ee41dab1bd96500910a30ad6f609ffcef52d"
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source(commit=COMMIT_A, tree=TREE_A, repository="owner/name"):
    return {"repository": repository, "commit": commit, "tree_sha256": tree}


def _module_manifest_doc(*, extra_mutants=None, diagnostic=False, runner="module"):
    mutants = [
        {"label": "rule-one", "anchor": "return True", "replacement": "return False"},
        {"label": "CONTROL", "control": True,
         "anchor": "def check", "replacement": "def  check"},
        {"label": "out-rule", "anchor": "x = 1", "replacement": "x = 2",
         "scope": "out_of_scope", "reason": "not this class"},
    ]
    if extra_mutants:
        mutants.extend(extra_mutants)
    doc = {
        "schema": ca.SCHEMA,
        "runner": runner,
        "implementation": "impl.py",
        "entrypoint": "check",
        "vectors": "vectors.json",
        "id_key": "vector_id",
        "default_group": "g",
        "mutants": {"g": mutants},
        "equivalent": {"g": [
            {"label": "eq-rule", "anchor": "return True",
             "replacement": "return True", "reason": "same under outcome_from"},
        ]},
    }
    if runner in ("process", "batch"):
        doc["repo_root"] = "."
        doc["implementation_sources"] = ["impl.py"]
        doc["entrypoint_command"] = ["python3", "impl.py"]
        doc["outcome_from"] = ["ok", "reason"]
        if diagnostic:
            doc["diagnostic_from"] = ["trace"]
        if runner == "process":
            doc["build"] = []
        if runner == "batch" and not diagnostic:
            pass
    return doc


def _write_module_workspace(root: Path, manifest_doc=None):
    (root / "impl.py").write_text("def check(v):\n    return True\n", encoding="utf-8")
    (root / "vectors.json").write_text(
        json.dumps({"vectors": [{"vector_id": "v1"}]}), encoding="utf-8")
    doc = manifest_doc if manifest_doc is not None else _module_manifest_doc()
    path = root / "manifest.json"
    raw = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.write_bytes(raw)
    bundle = root / "bundle.bin"
    bundle.write_bytes(b"mutation-bundle-bytes\n")
    return path, bundle, raw, bundle.read_bytes()


def _authored_origin():
    return {"kind": "authored", "source": _source()}


def _provenance_doc(*, class_id="example-declared-01", requested="declared",
                    manifest_sha256=None, bundle_sha256=None, origin=None,
                    authoring=None, events=None, distinctions=None,
                    relationship="same"):
    freeze = {
        "candidate": _source(COMMIT_A, TREE_A, "cand/repo"),
        "corpus": _source(COMMIT_B, TREE_B, "corp/repo"),
        "observation_declaration_sha256": OBS_A,
    }
    auth = authoring or {
        "mutation_author": "author-a",
        "candidate_builder": "author-a" if relationship == "same" else "builder-b",
        "relationship": relationship,
        "candidate_outcomes_seen": False,
    }
    vis = events or [{
        "ordinal": 0,
        "event": "selection-committed",
        "mutation_bundle_sha256": bundle_sha256 or ("sha256:" + "0" * 64),
        "actor": "author-a",
        "predecessor_event_sha256": None,
    }]
    dist = distinctions if distinctions is not None else [{
        "group": "g",
        "label": "rule-one",
        "channel": "outcome",
        "member": None,
    }]
    return {
        "schema": PROVENANCE_SCHEMA,
        "class_id": class_id,
        "requested_class": requested,
        "manifest_sha256": manifest_sha256 or ("sha256:" + "0" * 64),
        "mutation_bundle_sha256": bundle_sha256 or ("sha256:" + "0" * 64),
        "candidate_freeze": freeze,
        "authoring": auth,
        "visibility_events": vis,
        "origin": origin or _authored_origin(),
        "expected_distinctions": dist,
        "non_claims": list(CLASS_NON_CLAIMS),
    }


def _healthy_survivor_rows():
    return [
        producer_shaped_row(
            "control-killed", "CONTROL", moved=1,
            how="harness detects a change on this path"),
        producer_shaped_row("survived", "rule-one", how="0 vector(s) moved"),
    ]


def _healthy_survivor_report(*, manifest_sha256, runner="module"):
    rows = _healthy_survivor_rows()
    failures = [
        "1 mutant(s) survived; the required score is 100% of non-equivalent mutants",
    ]
    extras = {
        "manifest_sha256": manifest_sha256,
        "runner": runner,
        "control_status": "killed",
        "killed": 0,
        "survived": 1,
        "silent": 0,
        "equivalent": 0,
        "unexercised_out_of_scope": 0,
        "unproved": 0,
        "known_holes": 0,
        "declared_total": 1,
        "score_percent": 0.0,
        "adequate": False,
        "failures": failures,
        "mutants": rows,
        "tool_version": ca.VERSION,
        "tool_commit": COMMIT_A,
        "tool_source_state": "exact",
        "tool_content_sha256": CONTENT_A,
        "corpus_digest": "declared-corpus",
        "hole_ratio": 0.0,
        "out_of_scope_ratio": 0.0,
        "acknowledged_digests": 0,
        "diagnostic_channel_declared": False,
    }
    return producer_shaped_report(**extras)


def _null_score_report(*, manifest_sha256, runner="module"):
    rows = [
        producer_shaped_row(
            "control-error", "CONTROL", how="baseline failed"),
        producer_shaped_row("unproved", "rule-one", how="never ran"),
    ]
    return producer_shaped_report(
        runner=runner,
        manifest_sha256=manifest_sha256,
        control_status="error",
        killed=0, survived=0, silent=0, equivalent=0,
        unexercised_out_of_scope=0, unproved=1, known_holes=0,
        declared_total=1, score_percent=None, adequate=False,
        failures=["UNMUTATED baseline failed", "1 mutant(s) never ran, so this corpus was not measured against them"],
        mutants=rows,
        tool_version=ca.VERSION, tool_commit=None,
        tool_source_state="unresolved", tool_content_sha256=None,
        corpus_digest=None, hole_ratio=None, out_of_scope_ratio=None,
    )


def _write_json(path: Path, doc: dict) -> bytes:
    raw = ca.encode_class_provenance_v0(doc) if doc.get("schema") == PROVENANCE_SCHEMA else None
    if raw is None and doc.get("schema") == ATTEMPT_SCHEMA:
        raw = ca.encode_class_attempt_v0(doc)
    if raw is None:
        raw = (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(raw)
    return raw


def _guarded_parse(hostile: bytes):
    real = ca._parse_projection_json

    def wrapped(raw):
        if raw == hostile:
            raise AssertionError("parser sentinel")
        return real(raw)

    return wrapped


class ClassProvenanceV0(unittest.TestCase):
    def test_canonical_authored_declared_round_trip_is_stable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, manifest_raw, bundle_raw = _write_module_workspace(root)
            doc = _provenance_doc(
                manifest_sha256=ca._file_sha256(manifest_raw),
                bundle_sha256=ca._file_sha256(bundle_raw),
            )
            encoded = ca.encode_class_provenance_v0(doc)
            self.assertTrue(encoded.endswith(b"\n"))
            self.assertNotIn(b"\r", encoded)
            self.assertEqual(
                encoded,
                (json.dumps(json.loads(encoded), ensure_ascii=False, indent=2,
                            sort_keys=True) + "\n").encode("utf-8"),
            )
            path = root / "prov.json"
            path.write_bytes(encoded)
            loaded = ca.load_class_provenance_v0(
                path, manifest_path=manifest_path, mutation_bundle_path=bundle_path)
            self.assertEqual(loaded["schema"], PROVENANCE_SCHEMA)
            self.assertEqual(loaded["requested_class"], "declared")
            self.assertEqual(loaded["non_claims"], CLASS_NON_CLAIMS)
            again = ca.encode_class_provenance_v0(loaded)
            self.assertEqual(again, encoded)
            digest = hashlib.sha256(encoded).hexdigest()
            self.assertEqual(PINNED_DECLARED_PROVENANCE_SHA256, digest)

    def test_historical_fault_and_adaptive_origins_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, manifest_raw, bundle_raw = _write_module_workspace(root)
            man = ca._file_sha256(manifest_raw)
            bun = ca._file_sha256(bundle_raw)
            fault = _provenance_doc(
                class_id="example-fault-01", requested="real_fault",
                manifest_sha256=man, bundle_sha256=bun,
                origin={
                    "kind": "historical_fault",
                    "repository": "owner/name",
                    "faulty_commit": COMMIT_A,
                    "fixed_commit": COMMIT_B,
                    "reference": "https://example.invalid/issue/1",
                },
            )
            adaptive = _provenance_doc(
                class_id="example-adaptive-01", requested="adaptive",
                manifest_sha256=man, bundle_sha256=bun,
                origin={
                    "kind": "adaptive",
                    "source": _source(),
                    "predecessor_attempt_sha256": "sha256:" + "9" * 64,
                },
            )
            for doc in (fault, adaptive):
                encoded = ca.encode_class_provenance_v0(doc)
                path = root / (doc["class_id"] + ".json")
                path.write_bytes(encoded)
                loaded = ca.load_class_provenance_v0(
                    path, manifest_path=manifest_path, mutation_bundle_path=bundle_path)
                self.assertEqual(loaded["origin"]["kind"], doc["origin"]["kind"])
            mixed = copy.deepcopy(fault)
            mixed["origin"]["source"] = _source()
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_provenance_v0(mixed)

    def test_unknown_and_missing_and_overall_keys_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, manifest_raw, bundle_raw = _write_module_workspace(root)
            doc = _provenance_doc(
                manifest_sha256=ca._file_sha256(manifest_raw),
                bundle_sha256=ca._file_sha256(bundle_raw),
            )
            extra = copy.deepcopy(doc)
            extra["overall_score"] = 1
            with self.assertRaises(ca.ManifestError) as cm:
                ca.encode_class_provenance_v0(extra)
            self.assertIn("overall_score", str(cm.exception))
            extra2 = copy.deepcopy(doc)
            extra2["overall_adequate"] = True
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_provenance_v0(extra2)
            missing = copy.deepcopy(doc)
            del missing["origin"]
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_provenance_v0(missing)
            nested = copy.deepcopy(doc)
            nested["authoring"]["score"] = 1
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_provenance_v0(nested)

    def test_control_out_of_scope_equivalent_unknown_and_duplicate_distinctions_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, manifest_raw, bundle_raw = _write_module_workspace(root)
            man = ca._file_sha256(manifest_raw)
            bun = ca._file_sha256(bundle_raw)
            cases = [
                [{"group": "g", "label": "CONTROL", "channel": "outcome", "member": None}],
                [{"group": "g", "label": "out-rule", "channel": "outcome", "member": None}],
                [{"group": "g", "label": "eq-rule", "channel": "outcome", "member": None}],
                [{"group": "g", "label": "no-such", "channel": "outcome", "member": None}],
                [
                    {"group": "g", "label": "rule-one", "channel": "outcome", "member": None},
                    {"group": "g", "label": "rule-one", "channel": "outcome", "member": None},
                ],
            ]
            for dist in cases:
                doc = _provenance_doc(
                    manifest_sha256=man, bundle_sha256=bun, distinctions=dist)
                encoded = (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True)
                           + "\n").encode("utf-8")
                path = root / "p.json"
                path.write_bytes(encoded)
                with self.assertRaises(ca.ManifestError):
                    ca.load_class_provenance_v0(
                        path, manifest_path=manifest_path, mutation_bundle_path=bundle_path)

    def test_unsorted_events_gaps_and_malformed_predecessor_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_module_workspace(root)
            bun = "sha256:" + "8" * 64
            base_event = {
                "ordinal": 0, "event": "selection-committed",
                "mutation_bundle_sha256": bun, "actor": "author-a",
                "predecessor_event_sha256": None,
            }
            second = {
                "ordinal": 1, "event": "candidate-frozen",
                "mutation_bundle_sha256": bun, "actor": "author-a",
                "predecessor_event_sha256": "sha256:" + "7" * 64,
            }
            unsorted = _provenance_doc(events=[second, base_event], bundle_sha256=bun)
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_provenance_v0(unsorted)
            gap = _provenance_doc(events=[
                base_event,
                {**second, "ordinal": 2},
            ], bundle_sha256=bun)
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_provenance_v0(gap)
            bad_pred = _provenance_doc(events=[{
                **base_event, "predecessor_event_sha256": "not-a-digest",
            }], bundle_sha256=bun)
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_provenance_v0(bad_pred)

    def test_independent_equal_author_or_outcomes_seen_cannot_validate(self):
        equal = _provenance_doc(
            requested="independent", relationship="independent",
            authoring={
                "mutation_author": "same-person",
                "candidate_builder": "same-person",
                "relationship": "independent",
                "candidate_outcomes_seen": False,
            },
        )
        with self.assertRaises(ca.ManifestError) as cm:
            ca.encode_class_provenance_v0(equal)
        self.assertRegex(str(cm.exception).lower(), r"independent")
        seen = _provenance_doc(
            requested="independent", relationship="independent",
            authoring={
                "mutation_author": "author-a",
                "candidate_builder": "builder-b",
                "relationship": "independent",
                "candidate_outcomes_seen": True,
            },
        )
        with self.assertRaises(ca.ManifestError):
            ca.encode_class_provenance_v0(seen)

    def test_non_claims_are_byte_pinned(self):
        doc = _provenance_doc()
        omitted = copy.deepcopy(doc)
        omitted["non_claims"] = CLASS_NON_CLAIMS[:2]
        with self.assertRaises(ca.ManifestError):
            ca.encode_class_provenance_v0(omitted)
        added = copy.deepcopy(doc)
        added["non_claims"] = CLASS_NON_CLAIMS + ["extra"]
        with self.assertRaises(ca.ManifestError):
            ca.encode_class_provenance_v0(added)
        reordered = copy.deepcopy(doc)
        reordered["non_claims"] = list(reversed(CLASS_NON_CLAIMS))
        with self.assertRaises(ca.ManifestError):
            ca.encode_class_provenance_v0(reordered)

    def test_outcome_diagnostic_and_module_member_rules(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            process_doc = _module_manifest_doc(runner="process", diagnostic=True)
            process_doc["implementation"] = "impl.py"
            (root / "impl.py").write_text("print(1)\n", encoding="utf-8")
            (root / "vectors.json").write_text("{}", encoding="utf-8")
            man_path = root / "manifest.json"
            man_raw = json.dumps(process_doc).encode("utf-8")
            man_path.write_bytes(man_raw)
            bundle = root / "bundle.bin"
            bundle.write_bytes(b"bundle")
            man = ca._file_sha256(man_raw)
            bun = ca._file_sha256(b"bundle")
            ok = _provenance_doc(
                manifest_sha256=man, bundle_sha256=bun,
                distinctions=[
                    {"group": "g", "label": "rule-one", "channel": "diagnostic",
                     "member": "trace"},
                    {"group": "g", "label": "rule-one", "channel": "outcome",
                     "member": "ok"},
                ],
            )
            path = root / "p.json"
            path.write_bytes(
                (json.dumps(ok, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode())
            loaded = ca.load_class_provenance_v0(
                path, manifest_path=man_path, mutation_bundle_path=bundle)
            self.assertEqual(len(loaded["expected_distinctions"]), 2)
            bad_diag = copy.deepcopy(ok)
            bad_diag["expected_distinctions"] = [{
                "group": "g", "label": "rule-one", "channel": "diagnostic",
                "member": None,
            }]
            path.write_bytes(
                (json.dumps(bad_diag, ensure_ascii=False, indent=2, sort_keys=True)
                 + "\n").encode())
            with self.assertRaises(ca.ManifestError):
                ca.load_class_provenance_v0(
                    path, manifest_path=man_path, mutation_bundle_path=bundle)

    def test_module_accepts_only_outcome_null_member(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, manifest_raw, bundle_raw = _write_module_workspace(root)
            doc = _provenance_doc(
                manifest_sha256=ca._file_sha256(manifest_raw),
                bundle_sha256=ca._file_sha256(bundle_raw),
                distinctions=[{
                    "group": "g", "label": "rule-one", "channel": "outcome",
                    "member": "ok",
                }],
            )
            path = root / "p.json"
            path.write_bytes(
                (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode())
            with self.assertRaises(ca.ManifestError):
                ca.load_class_provenance_v0(
                    path, manifest_path=manifest_path, mutation_bundle_path=bundle_path)

    def test_test_names_uses_existing_expected_mover(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "impl.py").write_text("print(1)\n", encoding="utf-8")
            (root / "vectors.json").write_text("{}", encoding="utf-8")
            man_doc = {
                "schema": ca.SCHEMA,
                "runner": "batch",
                "repo_root": ".",
                "implementation_sources": ["impl.py"],
                "vectors": "vectors.json",
                "entrypoint_command": ["python3", "impl.py"],
                "outcome_parse": "test-names",
                "accepted_exit_codes": [0, 101],
                "mutants": {"g": [
                    {"label": "rule-one", "anchor": "a", "replacement": "b",
                     "expected_mover": "test_expected"},
                    {"label": "CONTROL", "control": True, "anchor": "c",
                     "replacement": "d"},
                ]},
            }
            man_raw = json.dumps(man_doc).encode("utf-8")
            man_path = root / "manifest.json"
            man_path.write_bytes(man_raw)
            bundle = root / "bundle.bin"
            bundle.write_bytes(b"b")
            bun = ca._file_sha256(b"b")
            man = ca._file_sha256(man_raw)
            wrong = _provenance_doc(
                manifest_sha256=man, bundle_sha256=bun,
                distinctions=[{
                    "group": "g", "label": "rule-one", "channel": "outcome",
                    "member": "test_other",
                }],
            )
            path = root / "p.json"
            path.write_bytes(
                (json.dumps(wrong, ensure_ascii=False, indent=2, sort_keys=True)
                 + "\n").encode())
            with self.assertRaises(ca.ManifestError):
                ca.load_class_provenance_v0(
                    path, manifest_path=man_path, mutation_bundle_path=bundle)
            ok = _provenance_doc(
                manifest_sha256=man, bundle_sha256=bun,
                distinctions=[{
                    "group": "g", "label": "rule-one", "channel": "outcome",
                    "member": "test_expected",
                }],
            )
            path.write_bytes(
                (json.dumps(ok, ensure_ascii=False, indent=2, sort_keys=True)
                 + "\n").encode())
            loaded = ca.load_class_provenance_v0(
                path, manifest_path=man_path, mutation_bundle_path=bundle)
            self.assertEqual(loaded["expected_distinctions"][0]["member"], "test_expected")
            diag = copy.deepcopy(ok)
            diag["expected_distinctions"] = [{
                "group": "g", "label": "rule-one", "channel": "diagnostic",
                "member": "trace",
            }]
            path.write_bytes(
                (json.dumps(diag, ensure_ascii=False, indent=2, sort_keys=True)
                 + "\n").encode())
            with self.assertRaises(ca.ManifestError):
                ca.load_class_provenance_v0(
                    path, manifest_path=man_path, mutation_bundle_path=bundle)


class ClassAttemptV0(unittest.TestCase):
    def _workspace(self, tmp: Path, report_factory=_healthy_survivor_report):
        manifest_path, bundle_path, manifest_raw, bundle_raw = _write_module_workspace(tmp)
        man = ca._file_sha256(manifest_raw)
        bun = ca._file_sha256(bundle_raw)
        prov = _provenance_doc(manifest_sha256=man, bundle_sha256=bun)
        prov_raw = ca.encode_class_provenance_v0(prov)
        prov_path = tmp / "prov.json"
        prov_path.write_bytes(prov_raw)
        report = report_factory(manifest_sha256=man)
        report_raw = ca.encode_report_v0(report)
        report_path = tmp / "report.json"
        report_path.write_bytes(report_raw)
        env_path = tmp / "env.bin"
        env_path.write_bytes(ENV_BYTES)
        return {
            "manifest_path": manifest_path,
            "bundle_path": bundle_path,
            "manifest_raw": manifest_raw,
            "prov": prov,
            "prov_path": prov_path,
            "prov_raw": prov_raw,
            "report": report,
            "report_path": report_path,
            "report_raw": report_raw,
            "env_path": env_path,
            "env_raw": ENV_BYTES,
        }

    def _attempt_doc(self, ws, *, status="completed", result=None, rows=None,
                     extras=None):
        report = ws["report"]
        doc = {
            "schema": ATTEMPT_SCHEMA,
            "attempt_id": "attempt-0001",
            "class_id": ws["prov"]["class_id"],
            "provenance_sha256": ca._file_sha256(ws["prov_raw"]),
            "manifest_sha256": ca._file_sha256(ws["manifest_raw"]),
            "report_sha256": ca._file_sha256(ws["report_raw"]),
            "environment_sha256": ca._file_sha256(ws["env_raw"]),
            "effective_class": "declared",
            "visibility_status": "declared",
            "predecessor_attempt_sha256": None,
            "status": status,
            "result": result or {
                "control_status": report["control_status"],
                "killed": report["killed"],
                "survived": report["survived"],
                "silent": report["silent"],
                "equivalent": report["equivalent"],
                "unexercised_out_of_scope": report["unexercised_out_of_scope"],
                "unproved": report["unproved"],
                "known_holes": report["known_holes"],
                "denominator": ca._scored_denominator(
                    report["killed"], report["survived"], report["silent"]),
                "score_percent": report["score_percent"],
                "adequate": report["adequate"],
                "failures": list(report["failures"]),
            },
            "rows": copy.deepcopy(rows if rows is not None else report["mutants"]),
            "non_claims": list(CLASS_NON_CLAIMS),
        }
        if extras:
            doc.update(extras)
        return doc

    def test_inadequate_healthy_survivor_is_completed_not_unproved(self):
        with tempfile.TemporaryDirectory() as d:
            ws = self._workspace(Path(d))
            derived = ca._derive_class_attempt_v0(
                attempt_id="attempt-0001",
                provenance_raw=ws["prov_raw"],
                manifest_raw=ws["manifest_raw"],
                report_raw=ws["report_raw"],
                environment_raw=ws["env_raw"],
                predecessor=None,
                classification={"effective_class": "declared",
                                "visibility_status": "declared"},
            )
            self.assertEqual(derived["status"], "completed")
            self.assertIs(derived["result"]["adequate"], False)
            self.assertEqual(derived["result"]["survived"], 1)
            self.assertEqual(derived["result"]["denominator"], 1)
            self.assertEqual(derived["rows"][1]["verdict"], "survived")
            encoded = ca.encode_class_attempt_v0(derived)
            path = Path(d) / "attempt.json"
            path.write_bytes(encoded)
            loaded = ca.load_class_attempt_v0(
                path,
                provenance_path=ws["prov_path"],
                manifest_path=ws["manifest_path"],
                report_path=ws["report_path"],
                environment_path=ws["env_path"],
            )
            self.assertEqual(loaded["status"], "completed")
            self.assertEqual(hashlib.sha256(encoded).hexdigest(),
                             hashlib.sha256(ca.encode_class_attempt_v0(loaded)).hexdigest())

    def test_null_score_and_unproved_rows_are_unproved_status(self):
        with tempfile.TemporaryDirectory() as d:
            ws = self._workspace(Path(d), report_factory=_null_score_report)
            derived = ca._derive_class_attempt_v0(
                attempt_id="attempt-0001",
                provenance_raw=ws["prov_raw"],
                manifest_raw=ws["manifest_raw"],
                report_raw=ws["report_raw"],
                environment_raw=ws["env_raw"],
                predecessor=None,
                classification={"effective_class": "declared",
                                "visibility_status": "declared"},
            )
            self.assertEqual(derived["status"], "unproved")
            self.assertIsNone(derived["result"]["score_percent"])
            rewritten = copy.deepcopy(derived)
            rewritten["status"] = "completed"
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_attempt_v0(rewritten)

    def test_publishable_derive_is_unreachable_until_f2(self):
        with self.assertRaises(ca.ManifestError) as cm:
            ca.derive_class_attempt_v0(
                attempt_id="attempt-0001",
                provenance_raw=b"{}",
                manifest_raw=b"{}",
                report_raw=b"{}",
                environment_raw=b"",
                predecessor=None,
                classification={"effective_class": "held_out",
                                "visibility_status": "hidden-until-freeze"},
            )
        self.assertRegex(str(cm.exception).lower(), r"unreachable|f2")

    def test_caller_counts_cannot_enter_an_encoded_attempt(self):
        with tempfile.TemporaryDirectory() as d:
            ws = self._workspace(Path(d))
            sig = inspect.signature(ca._derive_class_attempt_v0)
            for forbidden in ("killed", "survived", "denominator", "rows",
                              "result", "score_percent", "adequate", "status"):
                self.assertNotIn(forbidden, sig.parameters)
            derived = ca._derive_class_attempt_v0(
                attempt_id="attempt-0001",
                provenance_raw=ws["prov_raw"],
                manifest_raw=ws["manifest_raw"],
                report_raw=ws["report_raw"],
                environment_raw=ws["env_raw"],
                predecessor=None,
                classification={"effective_class": "declared",
                                "visibility_status": "declared"},
            )
            self.assertNotEqual(derived["result"]["killed"], 99)
            self.assertNotEqual(derived["result"]["denominator"], 99)
            derived["result"]["killed"] = 99
            derived["result"]["denominator"] = 99
            with self.assertRaises(ca.ManifestError) as cm:
                ca.encode_class_attempt_v0(derived)
            self.assertRegex(
                str(cm.exception).lower(),
                r"result\.(killed|denominator) does not match"
                r"|denominator does not match scored rows",
            )

    def test_digest_drift_refuses_independently_and_report_before_parse(self):
        with tempfile.TemporaryDirectory() as d:
            ws = self._workspace(Path(d))
            derived = ca._derive_class_attempt_v0(
                attempt_id="attempt-0001",
                provenance_raw=ws["prov_raw"],
                manifest_raw=ws["manifest_raw"],
                report_raw=ws["report_raw"],
                environment_raw=ws["env_raw"],
                predecessor=None,
                classification={"effective_class": "declared",
                                "visibility_status": "declared"},
            )
            path = Path(d) / "attempt.json"
            path.write_bytes(ca.encode_class_attempt_v0(derived))
            other_report = Path(d) / "other-report.json"
            hostile = b"{not-json"
            other_report.write_bytes(hostile)
            with mock.patch.object(
                    ca, "_parse_projection_json",
                    side_effect=_guarded_parse(hostile)):
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.load_class_attempt_v0(
                        path,
                        provenance_path=ws["prov_path"],
                        manifest_path=ws["manifest_path"],
                        report_path=other_report,
                        environment_path=ws["env_path"],
                    )
            self.assertRegex(str(cm.exception).lower(), r"digest")
            other_env = Path(d) / "other-env.bin"
            other_env.write_bytes(b"nope")
            with self.assertRaises(ca.ManifestError):
                ca.load_class_attempt_v0(
                    path,
                    provenance_path=ws["prov_path"],
                    manifest_path=ws["manifest_path"],
                    report_path=ws["report_path"],
                    environment_path=other_env,
                )

    def test_report_manifest_mismatch_refuses_when_each_digest_is_correct(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            ws = self._workspace(root)
            other_manifest = _module_manifest_doc()
            other_manifest["default_group"] = "other"
            other_raw = json.dumps(other_manifest).encode("utf-8")
            other_path = root / "other-manifest.json"
            other_path.write_bytes(other_raw)
            (root / "impl.py").write_text("def check(v):\n    return True\n", encoding="utf-8")
            (root / "vectors.json").write_text("{}", encoding="utf-8")
            derived = ca._derive_class_attempt_v0(
                attempt_id="attempt-0001",
                provenance_raw=ws["prov_raw"],
                manifest_raw=ws["manifest_raw"],
                report_raw=ws["report_raw"],
                environment_raw=ws["env_raw"],
                predecessor=None,
                classification={"effective_class": "declared",
                                "visibility_status": "declared"},
            )
            derived["manifest_sha256"] = ca._file_sha256(other_raw)
            path = root / "attempt.json"
            path.write_bytes(
                (json.dumps(derived, ensure_ascii=False, indent=2, sort_keys=True)
                 + "\n").encode())
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_class_attempt_v0(
                    path,
                    provenance_path=ws["prov_path"],
                    manifest_path=other_path,
                    report_path=ws["report_path"],
                    environment_path=ws["env_path"],
                )
            self.assertRegex(str(cm.exception).lower(), r"manifest")

    def test_silent_row_retains_moved_diagnostic(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, manifest_raw, bundle_raw = _write_module_workspace(root)
            man = ca._file_sha256(manifest_raw)
            bun = ca._file_sha256(bundle_raw)
            prov = _provenance_doc(manifest_sha256=man, bundle_sha256=bun)
            prov_raw = ca.encode_class_provenance_v0(prov)
            prov_path = root / "prov.json"
            prov_path.write_bytes(prov_raw)
            rows = [
                producer_shaped_row(
                    "control-killed", "CONTROL", moved=1,
                    how="harness detects a change on this path"),
                producer_shaped_row(
                    "silent", "rule-one", moved_diagnostic=2,
                    how="diagnostic channel moved on 2 vector(s)"),
            ]
            report = producer_shaped_report(
                runner="module",
                manifest_sha256=man,
                control_status="killed",
                killed=0, survived=0, silent=1, equivalent=0,
                unexercised_out_of_scope=0, unproved=0, known_holes=0,
                declared_total=1, score_percent=0.0, adequate=False,
                failures=["1 mutant(s) were silent"],
                mutants=rows,
                tool_version=ca.VERSION, tool_commit=COMMIT_A,
                tool_source_state="exact", tool_content_sha256=CONTENT_A,
                corpus_digest="c", hole_ratio=0.0, out_of_scope_ratio=0.0,
                diagnostic_channel_declared=True,
            )
            report_raw = ca.encode_report_v0(report)
            report_path = root / "report.json"
            report_path.write_bytes(report_raw)
            env_path = root / "env.bin"
            env_path.write_bytes(ENV_BYTES)
            derived = ca._derive_class_attempt_v0(
                attempt_id="attempt-0001",
                provenance_raw=prov_raw,
                manifest_raw=manifest_raw,
                report_raw=report_raw,
                environment_raw=ENV_BYTES,
                predecessor=None,
                classification={"effective_class": "declared",
                                "visibility_status": "declared"},
            )
            silent = [row for row in derived["rows"] if row["verdict"] == "silent"][0]
            self.assertIn("moved_diagnostic", silent)
            self.assertEqual(silent["moved_diagnostic"], 2)

    def test_predecessor_null_or_canonical_and_latest_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            ws = self._workspace(Path(d))
            derived = ca._derive_class_attempt_v0(
                attempt_id="attempt-0001",
                provenance_raw=ws["prov_raw"],
                manifest_raw=ws["manifest_raw"],
                report_raw=ws["report_raw"],
                environment_raw=ws["env_raw"],
                predecessor=None,
                classification={"effective_class": "declared",
                                "visibility_status": "declared"},
            )
            self.assertIsNone(derived["predecessor_attempt_sha256"])
            derived["predecessor_attempt_sha256"] = "sha256:" + "e" * 64
            ca.encode_class_attempt_v0(derived)
            derived["predecessor_attempt_sha256"] = "nope"
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_attempt_v0(derived)
            derived["predecessor_attempt_sha256"] = None
            derived["latest"] = True
            with self.assertRaises(ca.ManifestError) as cm:
                ca.encode_class_attempt_v0(derived)
            self.assertIn("latest", str(cm.exception))
            derived.pop("latest")
            derived["overall_score"] = 1
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_attempt_v0(derived)

    def test_canonical_attempt_bytes_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            ws = self._workspace(Path(d))
            derived = ca._derive_class_attempt_v0(
                attempt_id="attempt-0001",
                provenance_raw=ws["prov_raw"],
                manifest_raw=ws["manifest_raw"],
                report_raw=ws["report_raw"],
                environment_raw=ws["env_raw"],
                predecessor=None,
                classification={"effective_class": "declared",
                                "visibility_status": "declared"},
            )
            encoded = ca.encode_class_attempt_v0(derived)
            self.assertTrue(encoded.endswith(b"\n"))
            path = Path(d) / "attempt.json"
            path.write_bytes(encoded)
            loaded = ca.load_class_attempt_v0(
                path,
                provenance_path=ws["prov_path"],
                manifest_path=ws["manifest_path"],
                report_path=ws["report_path"],
                environment_path=ws["env_path"],
            )
            self.assertEqual(ca.encode_class_attempt_v0(loaded), encoded)
            self.assertEqual(
                hashlib.sha256(encoded).hexdigest(), PINNED_COMPLETED_ATTEMPT_SHA256)

    def test_hostile_report_row_uses_central_validator(self):
        src = inspect.getsource(ca.load_class_attempt_v0)
        self.assertIn("_require_report_rows", src)
        with tempfile.TemporaryDirectory() as d:
            ws = self._workspace(Path(d))
            hostile_report = copy.deepcopy(ws["report"])
            hostile_report["mutants"][1]["moved"] = -5
            raw = ca.encode_report_v0(hostile_report)
            path = Path(d) / "hostile-report.json"
            path.write_bytes(raw)
            with self.assertRaises(ca.ManifestError) as cm:
                ca._derive_class_attempt_v0(
                    attempt_id="attempt-0001",
                    provenance_raw=ws["prov_raw"],
                    manifest_raw=ws["manifest_raw"],
                    report_raw=raw,
                    environment_raw=ws["env_raw"],
                    predecessor=None,
                    classification={"effective_class": "declared",
                                    "visibility_status": "declared"},
                )
            self.assertRegex(str(cm.exception).lower(), r"moved|negative|int")


class ClassEvidenceHostileInputs(unittest.TestCase):
    def test_duplicate_nan_surrogate_overflow_nonobject_bool_ordinal_refuse(self):
        with self.assertRaises(ca.ManifestError):
            ca._parse_projection_json(b'{"a": 1, "a": 2}')
        with self.assertRaises(ca.ManifestError):
            ca._parse_projection_json(b'{"a": NaN}')
        with self.assertRaises(ca.ManifestError):
            ca._parse_projection_json(b'{"a": 1e999}')
        # Non-object roots are refused at the class codec root check, not by the
        # shared projection parser (arrays are valid JSON).
        parsed_array = ca._parse_projection_json(b"[]")
        self.assertIsInstance(parsed_array, list)
        # Provenance root must be an object with the class schema.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, _, _ = _write_module_workspace(root)
            array_path = root / "array.json"
            array_path.write_bytes(b"[]\n")
            with self.assertRaises(ca.ManifestError):
                ca.load_class_provenance_v0(
                    array_path, manifest_path=manifest_path,
                    mutation_bundle_path=bundle_path)
            bool_ord = _provenance_doc()
            bool_ord["visibility_events"][0]["ordinal"] = True
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_provenance_v0(bool_ord)
            lone = _provenance_doc()
            lone["authoring"]["mutation_author"] = "\ud800"
            with self.assertRaises(ca.ManifestError):
                ca.encode_class_provenance_v0(lone)

    def test_cap_plus_one_refuses_before_hash_or_parse(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, _, _ = _write_module_workspace(root)
            oversized = root / "over.json"
            oversized.write_bytes(b"x" * (ca.CLASS_INPUT_CAP_BYTES + 1))
            with mock.patch.object(
                    hashlib, "sha256",
                    side_effect=AssertionError("hashlib reached")) as hashed, \
                    mock.patch.object(
                        ca, "_parse_projection_json",
                        side_effect=AssertionError("parser sentinel")):
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.load_class_provenance_v0(
                        oversized, manifest_path=manifest_path,
                        mutation_bundle_path=bundle_path)
            self.assertIn("cap", str(cm.exception).lower())
            hashed.assert_not_called()

    def test_exact_cap_reaches_the_parser(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, _, _ = _write_module_workspace(root)
            exact = root / "exact.json"
            exact.write_bytes(b"{" + (b"x" * (ca.CLASS_INPUT_CAP_BYTES - 2)) + b"}")
            reached = {"parse": False}
            real = ca._parse_projection_json

            def wrapped(raw):
                reached["parse"] = True
                return real(raw)

            with mock.patch.object(ca, "_parse_projection_json", side_effect=wrapped):
                with self.assertRaises(ca.ManifestError):
                    ca.load_class_provenance_v0(
                        exact, manifest_path=manifest_path,
                        mutation_bundle_path=bundle_path)
            self.assertTrue(reached["parse"])

    def test_wrong_manifest_or_bundle_digest_refuses_before_parser_sentinel(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, manifest_raw, bundle_raw = _write_module_workspace(root)
            doc = _provenance_doc(
                manifest_sha256=ca._file_sha256(manifest_raw),
                bundle_sha256=ca._file_sha256(bundle_raw),
            )
            path = root / "prov.json"
            path.write_bytes(ca.encode_class_provenance_v0(doc))
            hostile_manifest = root / "hostile.json"
            hostile_bytes = b"{not json"
            hostile_manifest.write_bytes(hostile_bytes)
            with mock.patch.object(
                    ca, "_parse_projection_json",
                    side_effect=_guarded_parse(hostile_bytes)):
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.load_class_provenance_v0(
                        path, manifest_path=hostile_manifest,
                        mutation_bundle_path=bundle_path)
            self.assertRegex(str(cm.exception).lower(), r"digest")
            hostile_bundle = root / "hostile-bundle.bin"
            hostile_bundle.write_bytes(hostile_bytes)
            with mock.patch.object(
                    ca, "_parse_projection_json",
                    side_effect=_guarded_parse(hostile_bytes)):
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.load_class_provenance_v0(
                        path, manifest_path=manifest_path,
                        mutation_bundle_path=hostile_bundle)
            self.assertRegex(str(cm.exception).lower(), r"digest")

    @unittest.skipIf(not hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW is required")
    def test_symlink_fifo_directory_refuse_without_blocking(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, _, _ = _write_module_workspace(root)
            target = root / "real.json"
            target.write_bytes(b'{"schema":"%s"}' % PROVENANCE_SCHEMA.encode())
            link = root / "link.json"
            link.symlink_to(target)
            with mock.patch.object(
                    json, "loads",
                    side_effect=AssertionError("json.loads followed a symlink")):
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.load_class_provenance_v0(
                        link, manifest_path=manifest_path,
                        mutation_bundle_path=bundle_path)
            self.assertRegex(str(cm.exception).lower(), r"regular|symlink|follow")
            directory = root / "dir"
            directory.mkdir()
            with self.assertRaises(ca.ManifestError):
                ca.load_class_provenance_v0(
                    directory, manifest_path=manifest_path,
                    mutation_bundle_path=bundle_path)
            if hasattr(os, "mkfifo"):
                import signal
                import time

                class _Blocked(BaseException):
                    pass

                def alarm(_signum, _frame):
                    raise _Blocked("blocked on FIFO")

                pipe = root / "pipe"
                os.mkfifo(pipe)
                previous = signal.signal(signal.SIGALRM, alarm)
                signal.alarm(5)
                started = time.monotonic()
                try:
                    with self.assertRaises(ca.ManifestError):
                        ca.load_class_provenance_v0(
                            pipe, manifest_path=manifest_path,
                            mutation_bundle_path=bundle_path)
                    elapsed = time.monotonic() - started
                finally:
                    signal.alarm(0)
                    signal.signal(signal.SIGALRM, previous)
                self.assertLess(elapsed, 1.0)

    def test_no_nofollow_inode_substitution_refuses_before_replacement_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, manifest_raw, bundle_raw = _write_module_workspace(root)
            doc = _provenance_doc(
                manifest_sha256=ca._file_sha256(manifest_raw),
                bundle_sha256=ca._file_sha256(bundle_raw),
            )
            path = root / "prov.json"
            path.write_bytes(ca.encode_class_provenance_v0(doc))
            before = os.lstat(path)
            changed = mock.Mock(
                st_mode=before.st_mode,
                st_dev=before.st_dev,
                st_ino=before.st_ino + 1,
            )
            with mock.patch.object(ca.os, "O_NOFOLLOW", None, create=True), \
                    mock.patch.object(ca.os, "fstat", return_value=changed), \
                    mock.patch.object(
                        ca.os, "read",
                        side_effect=AssertionError("identity mismatch reached read")) as read:
                with self.assertRaisesRegex(
                        ca.ManifestError, "changed between lstat and open"):
                    ca.load_class_provenance_v0(
                        path, manifest_path=manifest_path,
                        mutation_bundle_path=bundle_path)
            read.assert_not_called()

    def test_canonical_input_bytes_are_required(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest_path, bundle_path, manifest_raw, bundle_raw = _write_module_workspace(root)
            doc = _provenance_doc(
                manifest_sha256=ca._file_sha256(manifest_raw),
                bundle_sha256=ca._file_sha256(bundle_raw),
            )
            canonical = ca.encode_class_provenance_v0(doc)
            # Semantically equal but not the codec wire form.
            messy = json.dumps(json.loads(canonical), indent=4).encode("utf-8")
            self.assertNotEqual(messy, canonical)
            path = root / "messy.json"
            path.write_bytes(messy)
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_class_provenance_v0(
                    path, manifest_path=manifest_path,
                    mutation_bundle_path=bundle_path)
            self.assertRegex(str(cm.exception).lower(), r"canonical|byte")

    def test_shared_class_encoder_and_input_cap(self):
        self.assertIs(ca.CLASS_INPUT_CAP_BYTES, ca.OUTPUT_CAP_BYTES)
        src = Path(ca.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        names = [node.name for node in tree.body if isinstance(node, ast.FunctionDef)]
        self.assertIn("_encode_class_artifact_v0", names)
        self.assertIn("_require_report_rows", inspect.getsource(ca.load_class_attempt_v0))
        self.assertIn("_encode_class_artifact_v0", inspect.getsource(ca.encode_class_provenance_v0))
        self.assertIn("_encode_class_artifact_v0", inspect.getsource(ca.encode_class_attempt_v0))
        self.assertNotIn("overall_score", ca.CLASS_PROVENANCE_SCHEMA)
        self.assertEqual(ca.CLASS_PROVENANCE_SCHEMA, PROVENANCE_SCHEMA)
        self.assertEqual(ca.CLASS_ATTEMPT_SCHEMA, ATTEMPT_SCHEMA)


class ClassEvidenceReportV0Preservation(unittest.TestCase):
    def test_tracked_report_v0_bytes_are_unchanged(self):
        for rel, digest in PRESERVED_REPORT_HASHES.items():
            path = REPO_ROOT / rel
            self.assertEqual(_sha256_file(path), digest, rel)

    def test_encode_report_v0_bytes_and_digest_are_unchanged(self):
        path = REPO_ROOT / "tests/fixtures/publication/valid-tersign/report.v0.json"
        raw = path.read_bytes()
        doc = json.loads(raw.decode("utf-8"))
        encoded = ca.encode_report_v0(doc)
        self.assertEqual(encoded, raw)
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), PRESERVED_REPORT_HASHES[
            "tests/fixtures/publication/valid-tersign/report.v0.json"])

    def test_no_second_semantic_report_validator(self):
        src = Path(ca.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        report_validators = [
            node.name for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name.startswith("_require_report")
        ]
        self.assertEqual(report_validators, ["_require_report_rows"])
        self.assertIn("_require_report_rows", inspect.getsource(ca.survivor_findings))
        self.assertIn("_require_report_rows", inspect.getsource(ca.diff_reports))

    def test_class_schemas_are_outside_report_v0(self):
        self.assertNotEqual(ca.REPORT_SCHEMA, PROVENANCE_SCHEMA)
        self.assertNotEqual(ca.REPORT_SCHEMA, ATTEMPT_SCHEMA)
        report_keys = ca._report_v0_keys("module")
        self.assertNotIn("effective_class", report_keys)
        self.assertNotIn("class_id", report_keys)
        self.assertNotIn("overall_score", report_keys)


if __name__ == "__main__":
    unittest.main()
