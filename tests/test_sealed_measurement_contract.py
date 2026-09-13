#!/usr/bin/env python3
"""Behavioral contract tests for sealed measurement identity. Stdlib only."""

from __future__ import annotations

import dataclasses
import json
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import aee_checker_sealed_materialize as materialize  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402
import aee_checker_sealed_authorize as authorize  # noqa: E402
import aee_checker_sealed_candidate as candidate  # noqa: E402
import aee_checker_sealed_execute as execute  # noqa: E402
import aee_checker_sealed_driver as driver  # noqa: E402
import contained_hosted_publication as publication  # noqa: E402
from aee_checker_sealed_common import PrepareError  # noqa: E402
from sealed_measurement_contract import (  # noqa: E402
    AEE_CHECKER_SEALED_CONTRACT,
    SealedMeasurementContract,
)


class SealedMeasurementContractTest(unittest.TestCase):
    def _alternate_sequence_contract(self):
        return dataclasses.replace(
            AEE_CHECKER_SEALED_CONTRACT,
            name="owned-fixture",
            mutation_group="owned",
            control_id="owned-control",
            site_ids=("owned-1", "owned-2"),
            operator="replace-condition",
            candidate_build=("printf", "build"),
            candidate_entrypoint=("printf", "run"),
        )

    def test_contract_is_closed_immutable_and_rejects_unsafe_identity(self):
        contract = AEE_CHECKER_SEALED_CONTRACT
        with self.assertRaises(dataclasses.FrozenInstanceError):
            contract.name = "changed"
        with self.assertRaises(ValueError):
            dataclasses.replace(contract, execution_paths=("../outside",))
        with self.assertRaises(ValueError):
            dataclasses.replace(contract, site_ids=("sealed-1", "sealed-1"))
        with self.assertRaises(ValueError):
            dataclasses.replace(contract, pin_digests=contract.pin_digests[:-1])
        with self.assertRaises(ValueError):
            dataclasses.replace(contract, adapter_sha256=None)
        with self.assertRaises(KeyError):
            contract.pin_digest("unknown.json")

    def test_alternate_contract_drives_materialized_identity_checks(self):
        manifest = b'{"corpusDigest":"fixture","vectors":[]}\n'
        alternate = dataclasses.replace(
            AEE_CHECKER_SEALED_CONTRACT,
            name="owned-fixture",
            corpus_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
            subject_tree_sha256="1" * 64,
            corpus_tree_sha256="2" * 64,
            corpus_id_count=1,
        )

        self.assertEqual(
            materialize.require_frozen_manifest_sha(manifest, contract=alternate),
            alternate.corpus_manifest_sha256,
        )
        materialize.require_frozen_trees("1" * 64, "2" * 64, contract=alternate)
        materialize.require_corpus_id_set(["owned-1"], contract=alternate)

        with self.assertRaisesRegex(PrepareError, "manifest sha"):
            materialize.require_frozen_manifest_sha(manifest)
        with self.assertRaisesRegex(PrepareError, "subject tree"):
            materialize.require_frozen_trees("1" * 64, "2" * 64)
        with self.assertRaisesRegex(PrepareError, "exactly 250"):
            materialize.require_corpus_id_set(["owned-1"])

    def test_legacy_aliases_have_one_contract_source_and_identity_includes_it(self):
        contract = AEE_CHECKER_SEALED_CONTRACT
        self.assertEqual(run.PHASE_A_INSTRUMENT_COMMIT, contract.instrument_commit)
        self.assertEqual(run.PHASE_A_PIN_DIGESTS, dict(contract.pin_digests))
        self.assertEqual(run.ADAPTER_DIGEST, contract.adapter_sha256)
        self.assertEqual(run.EXECUTION_PATHS, contract.execution_paths)
        self.assertIn("measurements/sealed_measurement_contract.py", contract.execution_paths)

    def test_prepare_validation_uses_the_supplied_contract(self):
        raw = (REPO_ROOT / "measurements" / "aee-go-run" / "prepare.v0.json").read_bytes()
        doc = json.loads(raw)
        parts = {key: doc[key] for key in run.PREPARE_PART_KEYS}
        parts["pins"]["instrument_commit"] = "1" * 40
        parts["materialized"]["corpus_id_count"] = 1
        alternate = dataclasses.replace(
            AEE_CHECKER_SEALED_CONTRACT,
            name="owned-fixture",
            instrument_commit="1" * 40,
            corpus_id_count=1,
        )

        rebuilt = run._prepare_v0_doc(parts, contract=alternate)
        self.assertEqual(rebuilt["pins"]["instrument_commit"], "1" * 40)
        self.assertEqual(rebuilt["materialized"]["corpus_id_count"], 1)
        with self.assertRaisesRegex(PrepareError, "instrument.commit"):
            run._prepare_v0_doc(parts)

    def test_archived_v0_prepare_remains_canonical_under_legacy_contract(self):
        raw = (REPO_ROOT / "measurements" / "aee-go-run" / "prepare.v0.json").read_bytes()
        doc = json.loads(raw)
        parts = {key: doc[key] for key in run.PREPARE_PART_KEYS}
        rebuilt = run._prepare_v0_doc(parts, contract=AEE_CHECKER_SEALED_CONTRACT)
        self.assertEqual(run.encode_json(rebuilt), raw)

    def test_alternate_contract_controls_authorized_sequence_and_mutation_binding(self):
        contract = self._alternate_sequence_contract()
        sites = {
            "sites": [
                {"id": "owned-1", "label": "one", "anchor": "a",
                 "replacement": "false", "manifest_replacement": "false"},
                {"id": "owned-2", "label": "two", "anchor": "b",
                 "replacement": "false", "manifest_replacement": "false"},
            ],
        }
        control = {"label": "control", "anchor": "c", "replacement": "false"}
        manifest = {
            "mutants": {
                "owned": [
                    {"id": "owned-control", "control": True, **control},
                    {"id": "owned-1", "control": False, "label": "one",
                     "anchor": "a", "replacement": "false"},
                    {"id": "owned-2", "control": False, "label": "two",
                     "anchor": "b", "replacement": "false"},
                ],
            },
        }

        steps = authorize.required_sequence(sites, contract=contract)
        self.assertEqual([step["id"] for step in steps],
                         ["baseline", "owned-control", "owned-1", "owned-2"])
        order = execute.bind_authorized_mutation_order(
            manifest=manifest, sites=sites, control=control, steps=steps,
            contract=contract,
        )
        self.assertEqual(order, ("control", "one", "two"))

    def test_alternate_contract_controls_candidate_commands(self):
        contract = self._alternate_sequence_contract()
        execution = {
            "build": list(contract.candidate_build),
            "entrypoint_command": list(contract.candidate_entrypoint),
        }
        script = candidate.candidate_script(execution, contract=contract)
        self.assertIn("printf build", script)
        self.assertIn("printf run", script)
        with self.assertRaisesRegex(PrepareError, "candidate execution contract"):
            candidate.candidate_script(execution)

    def test_hosted_legacy_root_names_the_aee_contract_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authorize_path = root / "authorize.json"
            prepare_path = root / "prepare.json"
            authorize_path.write_bytes(b"authorize")
            prepare_path.write_bytes(b"prepare")
            with mock.patch.object(driver, "run_authorized") as called:
                publication.default_sealed_execute(
                    authorize_path=authorize_path,
                    prepare_path=prepare_path,
                    pins_dir=root / "pins",
                    root=root,
                    envelope_dest=root / "envelope",
                    materialize_dest=root / "materialized",
                )
        self.assertIs(
            called.call_args.kwargs["contract"], AEE_CHECKER_SEALED_CONTRACT)


if __name__ == "__main__":
    unittest.main()
