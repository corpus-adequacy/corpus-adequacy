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


def _prepare_v2() -> bytes:
    """Canonical prepare.v2 bytes from the real codec, pinning the frozen v2 fixture."""
    from tests.test_aee_checker_sealed_candidate import _prepare_raw
    import contained_oci as contained
    return _prepare_raw(contained.CANDIDATE_RESOURCE_PROFILE_V2)


def _authorize(prepare_raw: bytes) -> bytes:
    return common.encode_json({
        "phase": auth.AUTHORIZE_PHASE,
        "prepare_schema": json.loads(prepare_raw)["schema"],
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
                    root=REPO_ROOT, execution_profile="contained-oci-v0")
            materialize.assert_not_called()
        with mock.patch.object(driver, "materialize_pinned") as materialize, \
                mock.patch.object(
                    driver, "execution_identity",
                    return_value={**prepare["execution"], "commit": "0" * 40}):
            with self.assertRaisesRegex(driver.DriverError, "execution"):
                driver.run_authorized(
                    authorize_raw=valid, prepare_raw=prepare_raw,
                    pins_dir=PREREG, materialize_dest=Path(d) / "stale",
                    root=REPO_ROOT, execution_profile="contained-oci-v0")
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
                        materialize_dest=dest, root=REPO_ROOT,
                        execution_profile="contained-oci-v0")
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
                        root=REPO_ROOT, execution_profile="contained-oci-v0")
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
                    root=REPO_ROOT, transport=object(),
                    execution_profile="contained-oci-v0")
        self.assertIs(result, expected)
        self.assertEqual(materialize.call_count, 1)
        self.assertEqual(materialize.call_args.args[1], dest)
        self.assertIsInstance(materialize.call_args.kwargs["budget"], common.MaterializeBudget)
        load.assert_called_once()
        self.assertEqual(load.call_args.kwargs["path_root"], dest)
        self.assertEqual(backend.call_args.kwargs["prepare_raw"], prepare_raw)
        self.assertEqual(backend.call_args.kwargs["execution_profile"], "contained-oci-v0")
        funnel.assert_called_once()
        self.assertIs(funnel.call_args.kwargs["execution_backend"], backend_value)
        self.assertEqual(funnel.call_args.kwargs["execution_profile"], "contained-oci-v0")


class _BelowTheEngineGate(Exception):
    """Raised just below the engine's profile/backend gate: reaching it means admission passed."""


class DriverThreadsTheResolvedProfile(unittest.TestCase):
    """#102 A3: the driver's profile reaches admission, the backend and the funnel unchanged.

    The funnel, `make_sealed_backend` and the engine's gate are the real ones, observed with
    `wraps`. Only what follows admission is replaced: identity, pins and materialization, as
    in the happy path above, and the engine just below its gate, where the backend's declared
    profile has already been compared with the resolved one. No backend is invoked.
    """

    def _through_the_real_funnel(self, prepare_raw, profile):
        prepare = json.loads(prepare_raw)
        built = []
        real_make = driver.runtime.make_sealed_backend

        def recording_make(**kwargs):
            built.append(real_make(**kwargs))
            return built[-1]

        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "materialized"
            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            with mock.patch.object(
                    driver, "execution_identity", return_value=prepare["execution"]), \
                    mock.patch.object(driver, "verify_phase_a_frozen", return_value={}), \
                    mock.patch.object(
                        driver, "materialize_pinned",
                        side_effect=lambda *_a, **_k: _materialized(dest, prepare)), \
                    mock.patch.object(driver.ca, "load_manifest_bytes", return_value=manifest), \
                    mock.patch.object(
                        driver.runtime, "make_sealed_backend",
                        side_effect=recording_make) as backend, \
                    mock.patch.object(
                        driver.execute, "run_execution_funnel",
                        wraps=driver.execute.run_execution_funnel) as funnel, \
                    mock.patch.object(
                        driver.ca, "ordered_declared_mutants",
                        side_effect=_BelowTheEngineGate) as below, \
                    self.assertRaises(_BelowTheEngineGate):
                driver.run_authorized(
                    authorize_raw=_authorize(prepare_raw), prepare_raw=prepare_raw,
                    pins_dir=PREREG, materialize_dest=dest, root=REPO_ROOT,
                    transport=object(), execution_profile=profile)
        self.assertEqual(below.call_count, 1)
        self.assertEqual(backend.call_count, 1)
        self.assertEqual(funnel.call_count, 1)
        self.assertEqual(backend.call_args.kwargs["execution_profile"], profile)
        self.assertEqual(funnel.call_args.kwargs["execution_profile"], profile)
        self.assertEqual(len(built), 1)
        self.assertIs(funnel.call_args.kwargs["execution_backend"], built[0])
        self.assertEqual(getattr(built[0], "execution_profile", None), profile)

    def test_v2_prepare_under_v1_reaches_one_funnel_and_a_v1_backend(self):
        self._through_the_real_funnel(_prepare_v2(), "contained-oci-v1")

    def test_v1_prepare_under_v0_reaches_one_funnel_and_a_v0_backend(self):
        self._through_the_real_funnel(_prepare_v1(), "contained-oci-v0")

    def _refused_before_identity(self, prepare_raw, profile):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with mock.patch.object(
                    driver, "execution_identity",
                    side_effect=AssertionError("driver advanced past admission")) as identity, \
                    mock.patch.object(
                        driver, "verify_phase_a_frozen",
                        side_effect=AssertionError("pins reached")) as pins, \
                    mock.patch.object(
                        driver, "materialize_pinned",
                        side_effect=AssertionError("materialization reached")) as materialize, \
                    self.assertRaises(driver.DriverError) as ctx:
                driver.run_authorized(
                    authorize_raw=_authorize(prepare_raw), prepare_raw=prepare_raw,
                    pins_dir=PREREG, materialize_dest=root / "never-created",
                    root=REPO_ROOT, execution_profile=profile)
            self.assertFalse((root / "never-created").exists())
        identity.assert_not_called()
        pins.assert_not_called()
        materialize.assert_not_called()
        return str(ctx.exception)

    def test_v2_prepare_under_v0_refuses_before_execution_identity(self):
        self.assertIn("prepare.v2 requires contained-oci-v1",
                      self._refused_before_identity(_prepare_v2(), "contained-oci-v0"))

    def test_v1_prepare_under_v1_refuses_before_execution_identity(self):
        self.assertIn("contained-oci-v1 admits only prepare.v2",
                      self._refused_before_identity(_prepare_v1(), "contained-oci-v1"))

    def test_identity_drift_under_v1_still_refuses_before_materialization(self):
        prepare_raw = _prepare_v2()
        prepare = json.loads(prepare_raw)
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(
                    driver, "execution_identity",
                    return_value={**prepare["execution"], "commit": "0" * 40}), \
                mock.patch.object(driver, "materialize_pinned") as materialize, \
                self.assertRaisesRegex(driver.DriverError, "execution identity drift"):
            driver.run_authorized(
                authorize_raw=_authorize(prepare_raw), prepare_raw=prepare_raw,
                pins_dir=PREREG, materialize_dest=Path(d) / "stale", root=REPO_ROOT,
                execution_profile="contained-oci-v1")
        materialize.assert_not_called()

    def test_toolchain_drift_under_v1_still_stops_before_runtime_or_funnel(self):
        prepare_raw = _prepare_v2()
        prepare = json.loads(prepare_raw)
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "materialized"

            def drifted(*_args, **_kwargs):
                mats = _materialized(dest, prepare)
                mats["toolchain"] = {**mats["toolchain"], "image_id": "sha256:" + "0" * 64}
                return mats

            with mock.patch.object(
                    driver, "execution_identity", return_value=prepare["execution"]), \
                    mock.patch.object(driver, "verify_phase_a_frozen", return_value={}), \
                    mock.patch.object(driver, "materialize_pinned", side_effect=drifted), \
                    mock.patch.object(driver.runtime, "make_sealed_backend") as backend, \
                    mock.patch.object(driver.execute, "run_execution_funnel") as funnel, \
                    self.assertRaisesRegex(driver.DriverError, "toolchain drift"):
                driver.run_authorized(
                    authorize_raw=_authorize(prepare_raw), prepare_raw=prepare_raw,
                    pins_dir=PREREG, materialize_dest=dest, root=REPO_ROOT,
                    execution_profile="contained-oci-v1")
        backend.assert_not_called()
        funnel.assert_not_called()

    def test_omitting_execution_profile_is_typeerror_not_an_implied_v0(self):
        import inspect
        parameter = inspect.signature(driver.run_authorized).parameters["execution_profile"]
        self.assertIs(parameter.default, inspect.Parameter.empty)
        prepare_raw = _prepare_v1()
        with mock.patch.object(
                driver, "validate_authorize",
                side_effect=AssertionError("omission reached authorization")), \
                self.assertRaises(TypeError):
            driver.run_authorized(
                authorize_raw=_authorize(prepare_raw), prepare_raw=prepare_raw,
                pins_dir=PREREG, materialize_dest=Path("never"), root=REPO_ROOT)

    def test_driver_code_names_no_profile_literal(self):
        """Code, not prose: the docstring may name profiles; no executable string may."""
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(driver.run_authorized))
        function = tree.body[0]
        docstring = function.body[0].value
        literals = [node.value for node in ast.walk(function)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and node is not docstring]
        self.assertFalse([v for v in literals if "contained-oci-v" in v], literals)


if __name__ == "__main__":
    unittest.main()
