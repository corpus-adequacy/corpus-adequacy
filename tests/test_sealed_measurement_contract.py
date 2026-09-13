#!/usr/bin/env python3
"""Behavioral contract tests for sealed measurement identity. Stdlib only."""

from __future__ import annotations

import dataclasses
import json
import hashlib
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import aee_checker_sealed_materialize as materialize  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402
from aee_checker_sealed_common import PrepareError  # noqa: E402
from sealed_measurement_contract import (  # noqa: E402
    AEE_CHECKER_SEALED_CONTRACT,
    SealedMeasurementContract,
)


class SealedMeasurementContractTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
