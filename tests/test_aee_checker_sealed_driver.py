#!/usr/bin/env python3
"""Synthetic provenance and ordering contract for the authorized AEE driver."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import aee_checker_sealed_authorize as auth  # noqa: E402
import aee_checker_sealed_common as common  # noqa: E402
import aee_checker_sealed_driver as driver  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402

PREREG = REPO_ROOT / "measurements" / "aee-checker-25b9dfa"
PREPARE_V0 = REPO_ROOT / "measurements" / "aee-go-run" / "prepare.v0.json"
MANIFEST_PATH = PREREG / "manifest.json"


def _prepare_v1() -> bytes:
    doc = json.loads(PREPARE_V0.read_text(encoding="utf-8"))
    doc["schema"] = run.PREPARE_V1_SCHEMA
    doc["candidate_profile"] = dict(common.CANDIDATE_RESOURCE_PROFILE)
    return common.encode_json(doc)


def _authorize(prepare_raw: bytes) -> bytes:
    return common.encode_json({
        "phase": auth.AUTHORIZE_PHASE,
        "prepare_schema": run.PREPARE_V1_SCHEMA,
        "prepare_sha256": hashlib.sha256(prepare_raw).hexdigest(),
        "schema": auth.AUTHORIZE_SCHEMA,
    })


def _materialized(root: Path, prepare: dict) -> dict:
    root.mkdir(exist_ok=True)
    result = dict(prepare["materialized"])
    result["toolchain"] = dict(prepare["toolchain"])
    for key in ("subject", "corpus", "vendor", "tool"):
        result[key] = root / key
        result[key].mkdir()
    return result


class DriverFailClosedOrder(unittest.TestCase):
    def test_authorization_and_current_identity_precede_materialization(self):
        prepare_raw = _prepare_v1()
        valid = _authorize(prepare_raw)
        prepare = json.loads(prepare_raw)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(
                driver, "materialize_pinned") as materialize, \
                mock.patch.object(
                    driver, "execution_identity", return_value=prepare["execution"]), \
                mock.patch.object(driver, "verify_phase_a_frozen", return_value={}):
            root = Path(d)
            with self.assertRaisesRegex(driver.DriverError, "exact keys|schema"):
                driver.run_authorized(
                    authorize_raw=b"{}", prepare_raw=prepare_raw,
                    pins_dir=PREREG, materialize_dest=root / "bad-auth",
                    root=REPO_ROOT)
            materialize.assert_not_called()
        with mock.patch.object(driver, "materialize_pinned") as materialize, \
                mock.patch.object(
                    driver, "execution_identity",
                    return_value={**prepare["execution"], "commit": "0" * 40}):
            with self.assertRaisesRegex(driver.DriverError, "execution"):
                driver.run_authorized(
                    authorize_raw=valid, prepare_raw=prepare_raw,
                    pins_dir=PREREG, materialize_dest=Path(d) / "stale",
                    root=REPO_ROOT)
        materialize.assert_not_called()

    def test_existing_materialization_destination_is_refused(self):
        prepare_raw = _prepare_v1()
        prepare = json.loads(prepare_raw)
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "existing"
            dest.mkdir()
            with mock.patch.object(
                    driver, "execution_identity", return_value=prepare["execution"]), \
                    mock.patch.object(driver, "verify_phase_a_frozen", return_value={}), \
                    mock.patch.object(driver, "materialize_pinned") as materialize:
                with self.assertRaisesRegex(driver.DriverError, "already exists"):
                    driver.run_authorized(
                        authorize_raw=_authorize(prepare_raw),
                        prepare_raw=prepare_raw, pins_dir=PREREG,
                        materialize_dest=dest, root=REPO_ROOT)
            materialize.assert_not_called()

    def test_rematerialization_drift_stops_before_runtime_or_funnel(self):
        prepare_raw = _prepare_v1()
        prepare = json.loads(prepare_raw)
        authorize_raw = _authorize(prepare_raw)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            dest = root / "materialized"

            def drifted_materialization(*_args, **_kwargs):
                mats = _materialized(dest, prepare)
                mats["corpus_tree_sha256"] = "0" * 64
                return mats

            with mock.patch.object(
                    driver, "execution_identity", return_value=prepare["execution"]), \
                    mock.patch.object(driver, "verify_phase_a_frozen", return_value={}), \
                    mock.patch.object(
                        driver, "materialize_pinned",
                        side_effect=drifted_materialization), \
                    mock.patch.object(
                        driver.ca, "load_manifest_bytes",
                        return_value=json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))), \
                    mock.patch.object(driver.runtime, "make_sealed_backend") as backend, \
                    mock.patch.object(driver.execute, "run_execution_funnel") as funnel:
                with self.assertRaisesRegex(driver.DriverError, "materialized"):
                    driver.run_authorized(
                        authorize_raw=authorize_raw, prepare_raw=prepare_raw,
                        pins_dir=PREREG, materialize_dest=dest,
                        root=REPO_ROOT)
            backend.assert_not_called()
            funnel.assert_not_called()


class DriverHappyPath(unittest.TestCase):
    def test_fake_materializer_reaches_one_bound_generic_funnel(self):
        prepare_raw = _prepare_v1()
        prepare = json.loads(prepare_raw)
        authorize_raw = _authorize(prepare_raw)
        expected = {"schema": "corpus-adequacy.report.v0", "marker": "fake"}
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            dest = root / "materialized"
            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            backend_value = object()

            def fake_materialization(*_args, **_kwargs):
                self.assertTrue(dest.is_dir())
                self.assertEqual(list(dest.iterdir()), [])
                return _materialized(dest, prepare)

            with mock.patch.object(
                    driver, "execution_identity", return_value=prepare["execution"]), \
                    mock.patch.object(driver, "verify_phase_a_frozen", return_value={"pins": "ok"}), \
                    mock.patch.object(
                        driver, "materialize_pinned",
                        side_effect=fake_materialization) as materialize, \
                    mock.patch.object(driver.ca, "load_manifest_bytes", return_value=manifest) as load, \
                    mock.patch.object(driver.runtime, "make_sealed_backend", return_value=backend_value) as backend, \
                    mock.patch.object(driver.execute, "run_execution_funnel", return_value=expected) as funnel:
                result = driver.run_authorized(
                    authorize_raw=authorize_raw, prepare_raw=prepare_raw,
                    pins_dir=PREREG, materialize_dest=dest,
                    root=REPO_ROOT, transport=object())
        self.assertIs(result, expected)
        self.assertEqual(materialize.call_count, 1)
        self.assertEqual(materialize.call_args.args[1], dest)
        self.assertIsInstance(materialize.call_args.kwargs["budget"], common.MaterializeBudget)
        load.assert_called_once()
        self.assertEqual(load.call_args.kwargs["path_root"], dest)
        self.assertEqual(backend.call_args.kwargs["prepare_raw"], prepare_raw)
        funnel.assert_called_once()
        self.assertIs(funnel.call_args.kwargs["execution_backend"], backend_value)
        self.assertEqual(funnel.call_args.kwargs["execution_profile"], "contained-oci-v0")


if __name__ == "__main__":
    unittest.main()
