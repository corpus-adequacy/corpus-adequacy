#!/usr/bin/env python3
"""Authorized AEE order binding into the sole generic process engine."""

from __future__ import annotations

import hashlib
import inspect
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import corpus_adequacy as ca  # noqa: E402
import aee_checker_sealed_authorize as auth  # noqa: E402
import aee_checker_sealed_common as common  # noqa: E402
import aee_checker_sealed_execute as exe  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402

PREREG = REPO_ROOT / "measurements" / "aee-checker-25b9dfa"
MANIFEST_PATH = PREREG / "manifest.json"
PREPARE_V0 = REPO_ROOT / "measurements" / "aee-go-run" / "prepare.v0.json"
SEALED_IDS = tuple("sealed-%d" % i for i in range(1, 8))
EXPECTED_LABELS = (
    "CONTROL immediate check_sealed refusal",
    "remove check_sealed guard: drop_count < 0",
    "remove check_sealed guard: !is_lower_hex64(observed_set)",
    "remove check_sealed guard: observed_set != ctx.observed_set",
    "remove check_sealed guard: !ctx.manifest_attacks.iter().any(|m| m == a)",
    "remove check_sealed guard: !still_armed",
    "remove check_sealed guard: !(drop_count == 0 || drop_bound.is_some_and(|b| drop_count <= b))",
    "remove check_sealed guard: posture != ctx.posture_digest",
)
NON_CLAIM_PHRASES = (
    "MC/DC", "atomic-subcondition adequacy", "complete mutation adequacy",
    "sandbox-efficacy", "certification", "ranking",
)


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


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


class AuthorizedPlanBinding(unittest.TestCase):
    def test_exact_frozen_rows_bind_control_then_sealed_1_through_7(self):
        sites = auth.load_frozen_sites(PREREG)
        control = common.load_strict((PREREG / "control.json").read_bytes())
        steps = auth.required_sequence(sites)
        order = exe.bind_authorized_mutation_order(
            manifest=_manifest(), sites=sites, control=control, steps=steps)
        self.assertEqual(order, EXPECTED_LABELS)

    def test_crosswired_missing_duplicate_reordered_or_surplus_row_is_refused(self):
        sites = auth.load_frozen_sites(PREREG)
        control = common.load_strict((PREREG / "control.json").read_bytes())
        steps = auth.required_sequence(sites)
        mutations = []
        crosswired = json.loads(json.dumps(sites))
        crosswired["sites"][0]["label"] = crosswired["sites"][1]["label"]
        mutations.append((crosswired, steps))
        for changed in (
            steps[:-1],
            steps + (steps[-1],),
            (steps[1], steps[0], *steps[2:]),
            (*steps, {"id": "surplus", "kind": "mutant", "operator": auth.GO_RUN_OPERATOR}),
        ):
            mutations.append((sites, changed))
        for changed_sites, changed_steps in mutations:
            with self.subTest(steps=changed_steps), self.assertRaisesRegex(
                    exe.ExecuteError, "sequence|manifest"):
                exe.bind_authorized_mutation_order(
                    manifest=_manifest(), sites=changed_sites,
                    control=control, steps=changed_steps)


class FunnelUsesTheGenericEngine(unittest.TestCase):
    def test_one_generic_engine_call_receives_the_authorized_order(self):
        prepare_raw = _prepare_v1()
        authorize_raw = _authorize(prepare_raw)
        manifest = _manifest()
        backend = object()
        expected = {"schema": ca.REPORT_SCHEMA, "marker": "one-report"}
        with mock.patch.object(ca, "_run_process", return_value=expected) as process:
            result = exe.run_execution_funnel(
                authorize_raw=authorize_raw,
                prepare_raw=prepare_raw,
                pins_dir=PREREG,
                manifest=manifest,
                manifest_path=MANIFEST_PATH,
                execution_backend=backend,
                execution_profile="contained-oci-v0",
            )
        self.assertIs(result, expected)
        process.assert_called_once_with(
            manifest, MANIFEST_PATH,
            execution_backend=backend,
            mutation_order=EXPECTED_LABELS,
            execution_profile="contained-oci-v0",
            separate_build_phase=False,
        )

    def test_driver_funnel_requires_prepare_v1_even_under_valid_v0_authorization(self):
        prepare_raw = PREPARE_V0.read_bytes()
        authorize_raw = auth.emit_authorize_v0(
            prepare_raw, Path(tempfile.mkdtemp()) / "authorize.v0.json")
        with mock.patch.object(ca, "_run_process") as process, self.assertRaisesRegex(
                exe.ExecuteError, "prepare.v1"):
            exe.run_execution_funnel(
                authorize_raw=authorize_raw, prepare_raw=prepare_raw,
                pins_dir=PREREG, manifest=_manifest(),
                manifest_path=MANIFEST_PATH, execution_backend=object(),
                execution_profile="contained-oci-v0")
        process.assert_not_called()

    def test_production_funnel_has_no_observation_classifier_or_private_report(self):
        source = Path(exe.__file__).read_text(encoding="utf-8")
        funnel = inspect.getsource(exe.run_execution_funnel)
        self.assertNotIn("classify_observation", source)
        self.assertNotIn("_report_v0", source)
        self.assertNotIn("score_percent", source)
        self.assertNotIn("for ", funnel)


class FunnelAdmitsPrepareByProfile(unittest.TestCase):
    """#102 A3: the funnel admits through the shared dispatcher, keyed by the resolved profile.

    Authorization is validated first; then `load_prepare_for_profile` admits prepare.v1 only
    under contained-oci-v0 and prepare.v2 only under contained-oci-v1. Every later boundary is
    a raising sentinel on the refusal paths, so a refusal that arrives late cannot pass.
    """

    def _funnel(self, prepare_raw, profile):
        return exe.run_execution_funnel(
            authorize_raw=_authorize(prepare_raw), prepare_raw=prepare_raw,
            pins_dir=PREREG, manifest=_manifest(), manifest_path=MANIFEST_PATH,
            execution_backend=object(), execution_profile=profile)

    def test_v2_under_v1_passes_the_dispatcher_and_reaches_the_engine_with_v1(self):
        prepare_raw = _prepare_v2()
        expected = {"schema": ca.REPORT_SCHEMA, "marker": "v1-report"}
        with mock.patch.object(
                exe, "load_prepare_for_profile",
                wraps=run.load_prepare_for_profile) as dispatcher, \
                mock.patch.object(ca, "_run_process", return_value=expected) as process:
            result = self._funnel(prepare_raw, "contained-oci-v1")
        self.assertIs(result, expected)
        dispatcher.assert_called_once_with(
            prepare_raw, execution_profile="contained-oci-v1")
        process.assert_called_once()
        self.assertEqual(process.call_args.kwargs["execution_profile"], "contained-oci-v1")
        self.assertEqual(process.call_args.kwargs["mutation_order"], EXPECTED_LABELS)

    def test_v1_under_v0_passes_the_dispatcher_and_reaches_the_engine_with_v0(self):
        prepare_raw = _prepare_v1()
        with mock.patch.object(ca, "_run_process", return_value={}) as process:
            self._funnel(prepare_raw, "contained-oci-v0")
        self.assertEqual(process.call_args.kwargs["execution_profile"], "contained-oci-v0")

    def _refused(self, prepare_raw, profile):
        with mock.patch.object(
                exe, "load_frozen_sites",
                side_effect=AssertionError("funnel advanced past admission")) as sites, \
                mock.patch.object(
                    ca, "_run_process",
                    side_effect=AssertionError("engine reached")) as process, \
                self.assertRaises(exe.ExecuteError) as ctx:
            self._funnel(prepare_raw, profile)
        sites.assert_not_called()
        process.assert_not_called()
        return str(ctx.exception)

    def test_prepare_v1_under_v1_is_refused_before_any_effect(self):
        self.assertIn("contained-oci-v1 admits only prepare.v2",
                      self._refused(_prepare_v1(), "contained-oci-v1"))

    def test_prepare_v2_under_v0_is_refused_before_any_effect(self):
        self.assertIn("prepare.v2 requires contained-oci-v1",
                      self._refused(_prepare_v2(), "contained-oci-v0"))

    def test_trusted_local_has_no_prepare_loader(self):
        self.assertIn("no PREPARE loader", self._refused(_prepare_v1(), "trusted-local"))

    def test_authorization_is_validated_before_admission(self):
        prepare_raw = _prepare_v2()
        with mock.patch.object(
                exe, "load_prepare_for_profile",
                side_effect=AssertionError("admission before authorization")) as dispatcher, \
                self.assertRaises(exe.ExecuteError):
            exe.run_execution_funnel(
                authorize_raw=b"{}", prepare_raw=prepare_raw, pins_dir=PREREG,
                manifest=_manifest(), manifest_path=MANIFEST_PATH,
                execution_backend=object(), execution_profile="contained-oci-v1")
        dispatcher.assert_not_called()

    def test_omitting_execution_profile_is_typeerror_not_an_implied_v0(self):
        parameter = inspect.signature(exe.run_execution_funnel).parameters[
            "execution_profile"]
        self.assertIs(parameter.default, inspect.Parameter.empty)
        prepare_raw = _prepare_v1()
        with mock.patch.object(
                exe, "validate_authorize",
                side_effect=AssertionError("omission reached authorization")), \
                self.assertRaises(TypeError):
            exe.run_execution_funnel(
                authorize_raw=_authorize(prepare_raw), prepare_raw=prepare_raw,
                pins_dir=PREREG, manifest=_manifest(), manifest_path=MANIFEST_PATH,
                execution_backend=object())


class PublicBoundary(unittest.TestCase):
    def test_main_does_not_start_an_experiment(self):
        with mock.patch.object(sys, "stderr", io.StringIO()):
            self.assertEqual(exe.main(["aee_checker_sealed_execute.py"]), 2)

    def test_non_claims_remain_in_code_and_tests(self):
        texts = (Path(exe.__file__).read_text(encoding="utf-8"),
                 Path(__file__).read_text(encoding="utf-8"))
        for phrase in NON_CLAIM_PHRASES:
            self.assertTrue(all(phrase in text for text in texts), phrase)


if __name__ == "__main__":
    unittest.main()
