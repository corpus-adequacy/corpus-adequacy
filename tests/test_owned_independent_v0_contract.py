#!/usr/bin/env python3
"""Slice B contract for the frozen independent selection (#199). No execution, no Docker."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "measurements")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import aee_checker_sealed_authorize as authorize  # noqa: E402
import aee_checker_sealed_candidate as candidate  # noqa: E402
import aee_checker_sealed_execute as execute  # noqa: E402
import aee_checker_sealed_run as sealed_run  # noqa: E402
import corpus_adequacy as ca  # noqa: E402
import owned_slice_b_local as slice_b  # noqa: E402
from aee_checker_sealed_common import PrepareError, load_strict  # noqa: E402
from hosted_rail_contract import OWNED_V1_RAIL  # noqa: E402
from sealed_measurement_contract import (  # noqa: E402
    AEE_CHECKER_SEALED_CONTRACT,
    OWNED_CONTAINED_V1_CONTRACT,
    OWNED_INDEPENDENT_V0_CONTRACT,
)

DECLARED = OWNED_CONTAINED_V1_CONTRACT
INDEPENDENT = OWNED_INDEPENDENT_V0_CONTRACT
DECLARED_PINS = ROOT / "measurements" / "owned-contained-v1"
INDEPENDENT_PINS = ROOT / "measurements" / "owned-independent-v0"
TRUNCATION = "value > maximum && value <= maximum.saturating_add(1)"
EXPECTED_DIFFERENCES = {
    "name", "pins_relpath", "pin_digests", "mutation_group", "site_ids", "operator",
    "site_replacement", "execution_paths",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ContractShape(unittest.TestCase):
    def test_site_replacement_is_required_and_the_first_contracts_keep_false(self):
        self.assertEqual(AEE_CHECKER_SEALED_CONTRACT.site_replacement, "false")
        self.assertEqual(DECLARED.site_replacement, "false")
        self.assertEqual(INDEPENDENT.site_replacement, TRUNCATION)
        for bad in ("", None, 0):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "site_replacement"):
                dataclasses.replace(INDEPENDENT, site_replacement=bad)

    def test_independent_differs_from_declared_only_in_the_selection(self):
        differing = {field.name for field in dataclasses.fields(DECLARED)
                     if getattr(DECLARED, field.name) != getattr(INDEPENDENT, field.name)}
        self.assertEqual(differing, EXPECTED_DIFFERENCES)
        self.assertEqual(INDEPENDENT.mutation_group, "independent")
        self.assertEqual(INDEPENDENT.control_id, DECLARED.control_id)
        self.assertEqual(INDEPENDENT.inert_control_ids, DECLARED.inert_control_ids)
        self.assertEqual(INDEPENDENT.site_ids, ("upper-guard-first-overflow-only",))

    def test_execution_paths_differ_only_in_the_manifest_path(self):
        only_declared = [p for p in DECLARED.execution_paths if p not in INDEPENDENT.execution_paths]
        only_independent = [p for p in INDEPENDENT.execution_paths
                            if p not in DECLARED.execution_paths]
        self.assertEqual(only_declared, ["measurements/owned-contained-v1/manifest.json"])
        self.assertEqual(only_independent, ["measurements/owned-independent-v0/manifest.json"])
        self.assertEqual(len(DECLARED.execution_paths), len(INDEPENDENT.execution_paths))

    def test_the_hosted_owned_rail_still_measures_the_declared_contract(self):
        self.assertIs(OWNED_V1_RAIL.measurement, DECLARED)


class Pins(unittest.TestCase):
    def test_pin_digests_match_the_files(self):
        for name, digest in INDEPENDENT.pin_digests:
            with self.subTest(name=name):
                self.assertEqual(_sha256(INDEPENDENT_PINS / name), digest)
        sealed_run.verify_phase_a_frozen(
            INDEPENDENT_PINS, adapter=ROOT / INDEPENDENT.adapter_relpath, contract=INDEPENDENT)

    def test_shared_pins_are_byte_equal_to_the_declared_ones(self):
        for name in ("control.json", "pins.json"):
            with self.subTest(name=name):
                self.assertEqual((INDEPENDENT_PINS / name).read_bytes(),
                                 (DECLARED_PINS / name).read_bytes())

    def test_frozen_selection_bytes_are_unchanged_since_slice_a(self):
        for name in slice_b.SELECTION_FILES:
            with self.subTest(name=name):
                blob = subprocess.run(
                    ["git", "-C", str(ROOT), "show",
                     "%s:measurements/owned-independent-v0/%s" % (slice_b.SELECTION_COMMIT,
                                                                   name)],
                    capture_output=True, check=True).stdout
                # Compare in the canonical LF form so a CRLF checkout does not fail the test.
                self.assertEqual(
                    (INDEPENDENT_PINS / name).read_bytes().replace(b"\r\n", b"\n"), blob)

    def test_sites_name_the_frozen_truncation(self):
        sites = load_strict((INDEPENDENT_PINS / "sites.json").read_bytes())
        self.assertEqual(sites, {"sites": [{
            "anchor": "if value > maximum",
            "id": "upper-guard-first-overflow-only",
            "label": "truncate owned-fixture upper guard to the first value above maximum",
            "manifest_replacement": "if " + TRUNCATION,
            "replacement": TRUNCATION,
        }]})


class AuthorizedSequence(unittest.TestCase):
    def _sites(self):
        return authorize.load_frozen_sites(INDEPENDENT_PINS, contract=INDEPENDENT)

    def _bind(self, sites, manifest=None):
        manifest = manifest or json.loads((INDEPENDENT_PINS / "manifest.json").read_text())
        control = load_strict((INDEPENDENT_PINS / "control.json").read_bytes())
        steps = authorize.required_sequence(sites, contract=INDEPENDENT)
        return execute.bind_authorized_mutation_order(
            manifest=manifest, sites=sites, control=control, steps=steps,
            contract=INDEPENDENT)

    def test_sequence_and_binding(self):
        steps = authorize.required_sequence(self._sites(), contract=INDEPENDENT)
        self.assertEqual([s["id"] for s in steps], [
            "baseline", "control-positive", "control-inert", "upper-guard-first-overflow-only"])
        self.assertEqual(self._bind(self._sites()), (
            "CONTROL immediate owned-fixture refusal",
            "CONTROL remove unreachable minimum sentinel",
            "truncate owned-fixture upper guard to the first value above maximum",
        ))

    def test_the_funnel_compares_against_the_contract_not_a_literal(self):
        # Break-to-RED for the authorize change: the independent sites refuse under "false".
        with self.assertRaises(authorize.AuthorizeError):
            authorize.required_sequence(
                self._sites(), contract=dataclasses.replace(INDEPENDENT, site_replacement="false"))
        declared_sites = authorize.load_frozen_sites(DECLARED_PINS, contract=DECLARED)
        with self.assertRaises(authorize.AuthorizeError):
            authorize.required_sequence(declared_sites, contract=dataclasses.replace(
                DECLARED, site_replacement=TRUNCATION))

    def test_a_greater_or_equal_replacement_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            pins = Path(raw)
            for name in ("control.json", "manifest.json", "pins.json"):
                shutil.copyfile(INDEPENDENT_PINS / name, pins / name)
            sites = load_strict((INDEPENDENT_PINS / "sites.json").read_bytes())
            sites["sites"][0]["replacement"] = "value >= maximum"
            sites["sites"][0]["manifest_replacement"] = "if value >= maximum"
            raw_sites = (json.dumps(sites, indent=2, sort_keys=True) + "\n").encode()
            (pins / "sites.json").write_bytes(raw_sites)
            with self.assertRaises(PrepareError):
                authorize.load_frozen_sites(pins, contract=INDEPENDENT)
            repinned = dataclasses.replace(INDEPENDENT, pin_digests=tuple(
                (n, hashlib.sha256(raw_sites).hexdigest() if n == "sites.json" else d)
                for n, d in INDEPENDENT.pin_digests), site_replacement="value >= maximum")
            loaded = authorize.load_frozen_sites(pins, contract=repinned)
            manifest = json.loads((pins / "manifest.json").read_text())
            control = load_strict((pins / "control.json").read_bytes())
            steps = authorize.required_sequence(loaded, contract=repinned)
            with self.assertRaisesRegex(execute.ExecuteError, "manifest site drift"):
                execute.bind_authorized_mutation_order(
                    manifest=manifest, sites=loaded, control=control, steps=steps,
                    contract=repinned)

    def test_a_manifest_group_other_than_independent_refuses(self):
        manifest = json.loads((INDEPENDENT_PINS / "manifest.json").read_text())
        manifest["mutants"] = {"owned": manifest["mutants"]["independent"]}
        with self.assertRaisesRegex(execute.ExecuteError, "manifest mutation groups"):
            self._bind(self._sites(), manifest)


class Adapter(unittest.TestCase):
    def test_independent_uses_the_owned_adapter_and_unknown_contracts_refuse(self):
        self.assertIs(candidate.sealed_adapter_for(INDEPENDENT),
                      candidate.sealed_adapter_for(DECLARED))
        with self.assertRaises(PrepareError):
            candidate.sealed_adapter_for(dataclasses.replace(INDEPENDENT, name="look-alike"))


class Provenance(unittest.TestCase):
    def test_provenance_encodes_and_loads_as_independent(self):
        doc = slice_b.build_provenance()
        self.assertEqual(doc["requested_class"], "independent")
        self.assertEqual(doc["manifest_sha256"],
                         "sha256:" + _sha256(INDEPENDENT_PINS / "manifest.json"))
        self.assertEqual([e["event"] for e in doc["visibility_events"]], ["selection-committed"])
        self.assertEqual(doc["expected_distinctions"], [{
            "group": "independent",
            "label": "truncate owned-fixture upper guard to the first value above maximum",
            "channel": "outcome", "member": "rows"}])
        with tempfile.TemporaryDirectory() as raw:
            result = slice_b.write_provenance(Path(raw))
            written = Path(raw) / "independent" / slice_b.PROVENANCE_FILENAME
            self.assertEqual(hashlib.sha256(written.read_bytes()).hexdigest(),
                             result["provenance_sha256"])
            with self.assertRaises(slice_b.SliceBError):
                slice_b.write_provenance(Path(raw))

    def test_the_observation_declaration_ignores_only_the_selection_fields(self):
        declared = (DECLARED_PINS / "manifest.json").read_bytes()
        independent = (INDEPENDENT_PINS / "manifest.json").read_bytes()
        self.assertEqual(slice_b.observation_declaration_sha256(declared),
                         slice_b.observation_declaration_sha256(independent))
        changed = json.loads(independent)
        changed["outcome_from"] = ["rows", "extra"]
        self.assertNotEqual(
            slice_b.observation_declaration_sha256(json.dumps(changed).encode()),
            slice_b.observation_declaration_sha256(independent))

    def test_seen_outcomes_or_a_non_independent_relationship_cannot_render_independent(self):
        for mutate, reason in (
            (lambda d: d["authoring"].update(candidate_outcomes_seen=True), "outcomes"),
            (lambda d: d["authoring"].update(
                candidate_builder=d["authoring"]["mutation_author"]), "distinct"),
            (lambda d: d["authoring"].update(relationship="same"), "relationship"),
            (lambda d: d["authoring"].update(relationship="unknown"), "relationship"),
        ):
            doc = copy.deepcopy(slice_b.build_provenance())
            mutate(doc)
            with self.subTest(authoring=doc["authoring"]):
                with self.assertRaises(ca.ManifestError):
                    ca.encode_class_provenance_v0(doc)


class Facade(unittest.TestCase):
    def test_the_selection_set_is_closed(self):
        self.assertEqual(set(slice_b.SELECTIONS), {"declared", "independent"})
        self.assertIs(slice_b.SELECTIONS["declared"], DECLARED)
        self.assertIs(slice_b.SELECTIONS["independent"], INDEPENDENT)
        with self.assertRaises(slice_b.SliceBError):
            slice_b.contract_for("aee")
        with self.assertRaises(SystemExit):
            slice_b.build_parser().parse_args(["run", "aee", "--out", "x"])

    def test_steps_without_their_inputs_refuse_before_any_effect(self):
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(slice_b.SliceBError):
                slice_b.authorize_selection("independent", Path(raw))
            with self.assertRaises(slice_b.SliceBError):
                slice_b.run("declared", Path(raw))
            with self.assertRaises(slice_b.SliceBError):
                slice_b.derive_class(Path(raw))
            self.assertEqual(slice_b.main(["run", "independent", "--out", raw]), 2)

    def test_identity_strings_are_pinned(self):
        self.assertEqual(slice_b.CLASS_ID, "owned-independent-v0")
        self.assertEqual(slice_b.ATTEMPT_ID, "owned-independent-v0-slice-b-01")
        self.assertEqual(slice_b.SELECTION_COMMIT, "9a73f1c0ab29856443d0a6c6f8fb19bf70989cc8")
        doc = slice_b.build_provenance()
        pins = json.loads((INDEPENDENT_PINS / "pins.json").read_text())
        self.assertEqual(doc["candidate_freeze"]["candidate"]["repository"],
                         pins["subject"]["repository"])
        self.assertEqual(doc["candidate_freeze"]["corpus"]["repository"],
                         pins["corpus"]["repository"])
        self.assertEqual(doc["origin"]["source"]["repository"],
                         "corpus-adequacy/corpus-adequacy")
        self.assertEqual(doc["candidate_freeze"]["candidate"]["tree_sha256"],
                         "sha256:" + INDEPENDENT.subject_tree_sha256)

    def test_the_validation_copy_must_be_the_pinned_subject_tree(self):
        from unittest import mock
        with mock.patch.object(slice_b, "tree_sha256", return_value="0" * 64):
            with self.assertRaises(slice_b.SliceBError) as ctx:
                with slice_b.manifest_beside_subject():
                    pass
        self.assertEqual(str(ctx.exception), "subject_tree")

    def test_the_facade_has_no_hosted_or_network_path(self):
        source = Path(slice_b.__file__).read_text(encoding="utf-8")
        for token in ("hosted_packet", "contained_hosted_publication", "urllib", "gh ",
                      "workflow_dispatch"):
            self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
