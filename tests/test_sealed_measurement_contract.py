#!/usr/bin/env python3
"""Behavioral contract tests for sealed measurement identity. Stdlib only."""

from __future__ import annotations

import dataclasses
import contextlib
import json
import hashlib
import subprocess
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
import aee_checker_sealed_runtime as runtime  # noqa: E402
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
            container_context_relpath="execution/owned-fixture",
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

    def test_prepare_forwards_the_same_nondefault_contract_to_materialization(self):
        from tests.test_aee_checker_sealed_run import ExplicitPrepareImage

        contract = self._alternate_sequence_contract()
        fixture = ExplicitPrepareImage()
        patches = fixture._patches()
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            active = [stack.enter_context(patcher) for patcher in patches]
            run.prepare(
                Path(directory) / "pins",
                Path(directory) / "out",
                root=Path(directory) / "root",
                image_id=fixture.IMAGE,
                contract=contract,
            )
        self.assertIs(active[5].call_args.kwargs["contract"], contract)

    def test_execute_forwards_the_same_nondefault_contract_to_authorization(self):
        class StopAfterAuthorization(Exception):
            pass

        contract = self._alternate_sequence_contract()
        with mock.patch.object(
                execute, "validate_authorize",
                side_effect=StopAfterAuthorization) as validate:
            with self.assertRaises(StopAfterAuthorization):
                execute.run_execution_funnel(
                    authorize_raw=b"authorize",
                    prepare_raw=b"prepare",
                    pins_dir=Path("pins"),
                    manifest={},
                    manifest_path=Path("manifest.json"),
                    execution_backend=object(),
                    execution_profile="contained-oci-v0",
                    contract=contract,
                )
        self.assertIs(validate.call_args.kwargs["contract"], contract)

    def test_runtime_forwards_the_same_nondefault_contract_to_candidate(self):
        contract = self._alternate_sequence_contract()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            materialized = {key: root / key for key in ("corpus", "vendor", "tool")}
            for path in materialized.values():
                path.mkdir()
            subject = root / "subject"
            subject.mkdir()
            manifest = {
                "_repo_root": subject,
                "accepted_exit_codes": [0],
                "unproved_exit_codes": [75],
                "runner": "batch",
                "outcome_from": ["rows"],
                "build": list(contract.candidate_build),
                "entrypoint_command": list(contract.candidate_entrypoint),
            }
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout='{"rows":["ok"]}', stderr="")
            with mock.patch.object(
                    runtime.candidate, "run_sealed_candidate",
                    return_value=completed) as sealed:
                backend = runtime.make_sealed_backend(
                    prepare_raw=b"prepare",
                    materialized=materialized,
                    execution_profile="contained-oci-v0",
                    contract=contract,
                )
                backend(manifest, [{"vector_id": "<batch>"}], rebuild=True)
        self.assertIs(sealed.call_args.kwargs["contract"], contract)

    def test_driver_forwards_one_nondefault_contract_to_both_lower_funnels(self):
        contract = self._alternate_sequence_contract()
        execution_identity = {"commit": "a" * 40, "paths": [], "content_sha256": "b" * 64}
        materialized_values = {
            key: value for key, value in {
                "corpus_digest": "c" * 64,
                "corpus_id_count": 1,
                "corpus_id_set_sha256": "d" * 64,
                "corpus_manifest_sha256": "e" * 64,
                "corpus_tree_sha256": "f" * 64,
                "subject_binary": False,
                "subject_check_rs_sha256": "1" * 64,
                "subject_tree_sha256": "2" * 64,
                "tool_config_sha256": "3" * 64,
                "vendor_outside_subject": True,
                "vendor_sha256": "4" * 64,
            }.items()
        }
        prepare_doc = {
            "execution": execution_identity,
            "materialize_ceilings": dict(run.MATERIALIZE_CEILINGS),
            "materialized": materialized_values,
            "toolchain": {"tool": "test"},
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pins = root / "pins"
            pins.mkdir()

            def fake_materialize(_pins, dest, **_kwargs):
                result = dict(materialized_values)
                result["toolchain"] = prepare_doc["toolchain"]
                for key in ("subject", "corpus", "vendor", "tool"):
                    path = Path(dest) / key
                    path.mkdir()
                    result[key] = path
                return result

            with mock.patch.object(driver, "validate_authorize"), \
                    mock.patch.object(driver, "load_prepare_for_profile",
                                      return_value=prepare_doc), \
                    mock.patch.object(driver, "execution_identity",
                                      return_value=execution_identity), \
                    mock.patch.object(driver, "verify_phase_a_frozen", return_value={}), \
                    mock.patch.object(driver, "materialize_pinned",
                                      side_effect=fake_materialize) as materializer, \
                    mock.patch.object(driver, "verify_file_digest", return_value=b"{}"), \
                    mock.patch.object(driver.ca, "load_manifest_bytes", return_value={}), \
                    mock.patch.object(driver.runtime, "make_sealed_backend",
                                      return_value=object()) as make_backend, \
                    mock.patch.object(driver.execute, "run_execution_funnel",
                                      return_value={}) as funnel:
                driver.run_authorized(
                    authorize_raw=b"authorize",
                    prepare_raw=b"prepare",
                    pins_dir=pins,
                    materialize_dest=root / "materialized",
                    root=root,
                    execution_profile="contained-oci-v0",
                    contract=contract,
                )

        self.assertIs(materializer.call_args.kwargs["contract"], contract)
        self.assertEqual(
            materializer.call_args.kwargs["template"],
            root / "execution" / "owned-fixture" / "cargo-config.toml",
        )
        self.assertIs(make_backend.call_args.kwargs["contract"], contract)
        self.assertIs(funnel.call_args.kwargs["contract"], contract)


if __name__ == "__main__":
    unittest.main()
