#!/usr/bin/env python3
"""Retained Slice B evidence: the declared and independent measurements (#199, #103).

Reads the retained bytes only. It runs no candidate, no Docker and no PREPARE.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "measurements")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import aee_checker_sealed_authorize as authorize  # noqa: E402
import aee_checker_sealed_run as sealed_run  # noqa: E402
import corpus_adequacy as ca  # noqa: E402
import envelope_collection as collection  # noqa: E402
import owned_slice_b_local as slice_b  # noqa: E402
from sealed_measurement_contract import (  # noqa: E402
    OWNED_CONTAINED_V1_CONTRACT,
    OWNED_INDEPENDENT_V0_CONTRACT,
)

EVIDENCE = ROOT / "measurements" / "owned-slice-b-5918ec4"
MEASURED_AT = "5918ec4495b64397b069c3cb3973e9153fee7e7a"
CONTRACTS = {"declared": OWNED_CONTAINED_V1_CONTRACT,
             "independent": OWNED_INDEPENDENT_V0_CONTRACT}
DIGESTS = {
    "README.md":
        "ca25cf55fcf5e33f24e6076e0e1551355229f6a8206dc1e467d689acc8dbd918",
    "declared/authorize.v0.json":
        "91aac51bd97dae1848fa3ae5bbd05a4dbe9edc90d35b43b241538f8b51bd9cdf",
    "declared/effective-envelope-collection.v0/collection-index.v0.json":
        "833af9dfcf8c75373c96067819442076df6c42c09f1e5743d84a8575d383f9b5",
    "declared/effective-envelope-collection.v0/member-0000.json":
        "2eb164f418c7678372632b1e29c5f28069edf7b1cb8015ebef6d88d9fc7d944e",
    "declared/effective-envelope-collection.v0/member-0001.json":
        "2eb164f418c7678372632b1e29c5f28069edf7b1cb8015ebef6d88d9fc7d944e",
    "declared/effective-envelope-collection.v0/member-0002.json":
        "2eb164f418c7678372632b1e29c5f28069edf7b1cb8015ebef6d88d9fc7d944e",
    "declared/effective-envelope-collection.v0/member-0003.json":
        "2eb164f418c7678372632b1e29c5f28069edf7b1cb8015ebef6d88d9fc7d944e",
    "declared/effective-envelope-collection.v0/member-0004.json":
        "2eb164f418c7678372632b1e29c5f28069edf7b1cb8015ebef6d88d9fc7d944e",
    "declared/prepare.v2.json":
        "9b3457b28d5a086af9f43661ae781f88359be869bb3717cedfb364f53b507d28",
    "declared/report.v0.json":
        "00e5c4dba313e2b490fd71c40fb5bc27f3a28e606600272c47ef7824b75e9831",
    "independent/authorize.v0.json":
        "a1ebeaaec3aba23fcea1e4d88838549f047ece4d89fad0b497765a7bf34c5386",
    "independent/class-attempt.v0.json":
        "29186aebb96950c264122712c279642e0de6c6b62e122e2c9026ffd0ab234164",
    "independent/class-provenance.v0.json":
        "ed764a70fd86825ae081815cd26e7545cc9bb4a8eabb436763ba1499ba48bc77",
    "independent/effective-envelope-collection.v0/collection-index.v0.json":
        "5c39c789947524eee5bf3bb64b1ed03a59c7d1c00e59215ffee6d1feef8c3232",
    "independent/effective-envelope-collection.v0/member-0000.json":
        "dd8a63520683fe1083c1145803bf67cfdcb5fed079c137981a162b339790b035",
    "independent/effective-envelope-collection.v0/member-0001.json":
        "dd8a63520683fe1083c1145803bf67cfdcb5fed079c137981a162b339790b035",
    "independent/effective-envelope-collection.v0/member-0002.json":
        "dd8a63520683fe1083c1145803bf67cfdcb5fed079c137981a162b339790b035",
    "independent/effective-envelope-collection.v0/member-0003.json":
        "dd8a63520683fe1083c1145803bf67cfdcb5fed079c137981a162b339790b035",
    "independent/prepare.v2.json":
        "ae2686d6bfa34fffedc0fb68698a54abcd6bc6f7cc3995e35cfb3dd22992b62b",
    "independent/report.v0.json":
        "5290f5eb22358e92adfdb22662c360ffe1e18303a3eb8f839a60ff2f4264d314",
}


def _read(rel: str) -> bytes:
    return (EVIDENCE / rel).read_bytes()


def _doc(rel: str) -> dict:
    return json.loads(_read(rel).decode("utf-8"))


class RetainedBytes(unittest.TestCase):
    def test_every_retained_file_is_pinned_and_nothing_else_is_there(self):
        found = {str(p.relative_to(EVIDENCE)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in EVIDENCE.rglob("*") if p.is_file()}
        self.assertEqual(found, DIGESTS)

    def test_no_working_directory_leaked_into_the_evidence(self):
        for name in ("materialize", "prepare", "subject", "vendor", "tool"):
            self.assertFalse(list(EVIDENCE.rglob(name)), name)


class Reports(unittest.TestCase):
    def test_the_declared_selection_distinguishes_both_of_its_mutants(self):
        report = _doc("declared/report.v0.json")
        self.assertEqual(
            {key: report[key] for key in
             ("killed", "survived", "silent", "unproved", "equivalent", "declared_total",
              "control_status", "adequate", "score_percent")},
            {"killed": 2, "survived": 0, "silent": 0, "unproved": 0, "equivalent": 0,
             "declared_total": 2, "control_status": "killed", "adequate": True,
             "score_percent": 100.0})

    def test_the_independent_selection_finds_one_healthy_survivor(self):
        report = _doc("independent/report.v0.json")
        self.assertEqual(
            {key: report[key] for key in
             ("killed", "survived", "silent", "unproved", "equivalent", "declared_total",
              "control_status", "adequate", "score_percent")},
            {"killed": 0, "survived": 1, "silent": 0, "unproved": 0, "equivalent": 0,
             "declared_total": 1, "control_status": "killed", "adequate": False,
             "score_percent": 0.0})

    def test_both_reports_name_this_tool_revision_and_their_own_manifest(self):
        for selection, contract in CONTRACTS.items():
            with self.subTest(selection=selection):
                report = _doc("%s/report.v0.json" % selection)
                self.assertEqual(report["tool_commit"], MEASURED_AT)
                self.assertEqual(report["tool_source_state"], "exact")
                manifest = (ROOT.joinpath(*contract.pins_relpath) / "manifest.json").read_bytes()
                self.assertEqual(report["manifest_sha256"],
                                 "sha256:" + hashlib.sha256(manifest).hexdigest())

    def test_the_two_denominators_never_meet(self):
        declared = _read("declared/report.v0.json")
        independent = _read("independent/report.v0.json")
        self.assertNotEqual(declared, independent)
        for rel in DIGESTS:
            raw = _read(rel)
            self.assertNotIn(b'"declared_total": 2', raw if rel.startswith("independent") else b"")
            self.assertNotIn(b'"declared_total": 1', raw if rel.startswith("declared") else b"")


class OneEnvironment(unittest.TestCase):
    def _prepare(self, selection: str) -> dict:
        return _doc("%s/prepare.v2.json" % selection)

    def test_the_two_selections_ran_in_the_same_environment(self):
        declared, independent = self._prepare("declared"), self._prepare("independent")
        for key in ("toolchain", "runtime", "materialize_ceilings", "network", "oci",
                    "candidate_profile", "materialized"):
            if key in declared or key in independent:
                with self.subTest(key=key):
                    self.assertEqual(declared.get(key), independent.get(key))
        self.assertEqual(declared["execution"]["commit"], independent["execution"]["commit"])
        self.assertEqual(declared["execution"]["commit"], MEASURED_AT)

    def test_the_candidate_image_is_shared_and_only_the_inert_probe_differs(self):
        declared, independent = self._prepare("declared"), self._prepare("independent")
        # The candidate toolchain image is pinned by digest, so both runs used the same one.
        self.assertEqual(declared["toolchain"]["image_id"], independent["toolchain"]["image_id"])
        # The inert probe is built per PREPARE, so its host-local id differs by construction.
        # It is not the candidate image and never runs candidate code.
        self.assertEqual(declared["image"]["kind"], "inert-probe")
        self.assertEqual(declared["image"]["id_scope"], "host-local")
        self.assertNotEqual(declared["image"]["id"], independent["image"]["id"])
        self.assertNotIn(declared["image"]["id"], (declared["toolchain"]["image_id"],
                                                   independent["toolchain"]["image_id"]))

    def test_the_execution_identities_differ_only_by_the_manifest_path(self):
        declared, independent = self._prepare("declared"), self._prepare("independent")
        self.assertNotEqual(declared["execution"]["content_sha256"],
                            independent["execution"]["content_sha256"])
        paths = {selection: set(contract.execution_paths)
                 for selection, contract in CONTRACTS.items()}
        self.assertEqual(paths["declared"] ^ paths["independent"],
                         {"measurements/owned-contained-v1/manifest.json",
                          "measurements/owned-independent-v0/manifest.json"})

    def test_each_execution_identity_still_matches_this_checkout(self):
        # If an execution path changes, this fails: the retained evidence then belongs to an
        # older identity and a fresh PREPARE is required before any new measurement.
        for selection, contract in CONTRACTS.items():
            with self.subTest(selection=selection):
                self.assertEqual(
                    sealed_run.execution_identity(ROOT, contract=contract)["content_sha256"],
                    self._prepare(selection)["execution"]["content_sha256"])


class Collections(unittest.TestCase):
    def _loaded(self, selection: str):
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "collection"
            shutil.copytree(EVIDENCE / selection / "effective-envelope-collection.v0", dest)
            return collection.load_collection(dest)

    def test_each_collection_is_v1_verified_and_bound_to_its_report(self):
        expected_steps = {
            "declared": ["baseline", "control-positive", "control-inert", "negative-guard",
                         "upper-guard"],
            "independent": ["baseline", "control-positive", "control-inert",
                            "upper-guard-first-overflow-only"],
        }
        for selection, contract in CONTRACTS.items():
            with self.subTest(selection=selection):
                loaded = self._loaded(selection)
                index = loaded["index"]
                self.assertEqual(index["schema"], collection.COLLECTION_SCHEMA_V1)
                self.assertEqual(index["execution_commit"], MEASURED_AT)
                report = _read("%s/report.v0.json" % selection)
                self.assertEqual(index["report_sha256"], hashlib.sha256(report).hexdigest())
                self.assertEqual(index["attempts"], len(loaded["members"]))
                steps = [row["step"] for row in loaded["ledger"]]
                self.assertEqual(
                    [step["id"] or "baseline" for step in steps], expected_steps[selection])
                self.assertEqual({step["group"] for step in steps},
                                 {contract.mutation_group})
                self.assertEqual(
                    [step["id"] for step in steps][1:],
                    list(authorize.required_sequence(
                        authorize.load_frozen_sites(
                            ROOT.joinpath(*contract.pins_relpath), contract=contract),
                        contract=contract)[1:][i]["id"] for i in range(len(steps) - 1)))
                self.assertTrue(all(row["state"] == "recorded" for row in loaded["ledger"]))
                self.assertTrue(all(row["returncode"] == 0 for row in loaded["ledger"]))
                for member in loaded["members"]:
                    self.assertEqual(
                        (member["candidate_outcome"], member["envelope_status"],
                         member["cleanup"], member["publication_permission"]),
                        ("completed", "verified", "removed-and-absent", "permitted"))
                    self.assertEqual(member["effective"]["network_mode"], "none")
                    self.assertEqual(member["effective"]["user"], "65532:65532")
                    self.assertEqual(member["requested"]["execution_profile"],
                                     "contained-oci-v1")


class ClassEvidence(unittest.TestCase):
    def test_the_independent_attempt_is_a_completed_independent_class(self):
        with slice_b.manifest_beside_subject() as manifest_path:
            attempt = ca.load_class_attempt_v0(
                EVIDENCE / "independent" / "class-attempt.v0.json",
                provenance_path=EVIDENCE / "independent" / "class-provenance.v0.json",
                manifest_path=manifest_path,
                report_path=EVIDENCE / "independent" / "report.v0.json",
                environment_path=EVIDENCE / "independent" / "prepare.v2.json")
        self.assertEqual(
            (attempt["status"], attempt["effective_class"], attempt["visibility_status"]),
            ("completed", "independent", "declared"))
        self.assertEqual(attempt["result"]["survived"], 1)
        self.assertEqual(attempt["result"]["killed"], 0)
        self.assertEqual(attempt["result"]["control_status"], "killed")
        self.assertEqual(attempt["result"]["denominator"], 1)
        self.assertEqual(
            [(row["label"], row["verdict"]) for row in attempt["rows"]],
            [("CONTROL immediate owned-fixture refusal", "control-killed"),
             ("CONTROL remove unreachable minimum sentinel", "control-unchanged"),
             ("truncate owned-fixture upper guard to the first value above maximum",
              "survived")])

    def test_the_attempt_binds_this_report_and_this_environment(self):
        attempt = _doc("independent/class-attempt.v0.json")
        self.assertEqual(attempt["report_sha256"],
                         "sha256:" + DIGESTS["independent/report.v0.json"])
        self.assertEqual(attempt["environment_sha256"],
                         "sha256:" + DIGESTS["independent/prepare.v2.json"])
        self.assertEqual(attempt["provenance_sha256"],
                         "sha256:" + DIGESTS["independent/class-provenance.v0.json"])
        self.assertIsNone(attempt["predecessor_attempt_sha256"])

    def test_the_provenance_still_binds_the_frozen_selection(self):
        contract = OWNED_INDEPENDENT_V0_CONTRACT
        pins = ROOT.joinpath(*contract.pins_relpath)
        with slice_b.manifest_beside_subject() as manifest_path:
            doc = ca.load_class_provenance_v0(
                EVIDENCE / "independent" / "class-provenance.v0.json",
                manifest_path=manifest_path,
                mutation_bundle_path=pins / "mutation-bundle.json")
        self.assertEqual(doc["requested_class"], "independent")
        self.assertEqual(doc["authoring"]["relationship"], "independent")
        self.assertFalse(doc["authoring"]["candidate_outcomes_seen"])
        self.assertEqual(doc["manifest_sha256"],
                         "sha256:" + hashlib.sha256((pins / "manifest.json").read_bytes())
                         .hexdigest())

    def test_the_declared_selection_has_no_class_artifacts(self):
        for name in ("class-provenance.v0.json", "class-attempt.v0.json"):
            self.assertFalse((EVIDENCE / "declared" / name).exists(), name)


if __name__ == "__main__":
    unittest.main()
