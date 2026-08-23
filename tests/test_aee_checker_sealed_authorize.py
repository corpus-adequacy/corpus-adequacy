#!/usr/bin/env python3
"""Phase C GO-RUN authorization contract for the frozen inverse-AEE experiment. Standard library only.

Binds exact prepare.v0 bytes. Does not run the checker, baseline, control,
or mutants. Does not emit report.v0. Public non-claims: not MC/DC, not
atomic-subcondition adequacy, not complete mutation adequacy, not
sandbox-efficacy, not certification, not ranking.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import aee_checker_sealed_authorize as auth  # noqa: E402
import aee_checker_sealed_common as common  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402

PREREG = REPO_ROOT / "measurements" / "aee-checker-25b9dfa"
GO_RUN_DIR = REPO_ROOT / "measurements" / "aee-go-run"
PREPARE_PATH = GO_RUN_DIR / "prepare.v0.json"
AUTHORIZE_PATH = GO_RUN_DIR / "authorize.v0.json"
DOCS_PATH = GO_RUN_DIR / "README.md"
SITES_DIGEST = "6223a15c5db5a7c19c4633474875615ec61f3d710e092939f46b80ee986e0c4c"
PREPARE_DIGEST = "90674e74097d93d84e6794b4c6b3294ce702949f41af2e582807c3910ccf4c79"
PHASE_A_FILES = ("control.json", "manifest.json", "pins.json", "sites.json")
SEALED_IDS = tuple("sealed-%d" % i for i in range(1, 8))
NON_CLAIM_PHRASES = (
    "MC/DC",
    "atomic-subcondition adequacy",
    "complete mutation adequacy",
    "sandbox-efficacy",
    "certification",
    "ranking",
)
FORBIDDEN_AUTHORIZE_KEYS = (
    "execution", "image", "toolchain", "sequence", "provenance",
)


def _prepare_raw() -> bytes:
    return PREPARE_PATH.read_bytes()


def _sites() -> dict:
    return json.loads((PREREG / "sites.json").read_text(encoding="utf-8"))


def _authorize_doc(prepare_raw: bytes, **overrides) -> dict:
    doc = {
        "phase": "authorize",
        "prepare_schema": run.PREPARE_SCHEMA,
        "prepare_sha256": hashlib.sha256(prepare_raw).hexdigest(),
        "schema": auth.AUTHORIZE_SCHEMA,
    }
    doc.update(overrides)
    return doc


def _dump(doc) -> bytes:
    return common.encode_json(doc)


def _rewrite_prepare(mutator):
    doc = json.loads(_prepare_raw())
    mutator(doc)
    return _dump(doc)


class CommittedArtifacts(unittest.TestCase):
    def test_prepare_is_outside_frozen_phase_a_and_exact(self):
        names = sorted(p.name for p in PREREG.iterdir())
        self.assertEqual(list(names), list(PHASE_A_FILES))
        self.assertFalse((PREREG / "prepare.v0.json").exists())
        self.assertFalse((PREREG / "authorize.v0.json").exists())
        raw = _prepare_raw()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), PREPARE_DIGEST)
        self.assertTrue(raw.endswith(b"\n"))

    def test_committed_authorize_is_filled_and_exactly_four_keys(self):
        raw = AUTHORIZE_PATH.read_bytes()
        doc = json.loads(raw)
        self.assertEqual(set(doc), {"phase", "prepare_schema", "prepare_sha256", "schema"})
        for key in FORBIDDEN_AUTHORIZE_KEYS:
            self.assertNotIn(key, doc)
        self.assertTrue(doc["prepare_sha256"])
        self.assertNotEqual(doc["prepare_sha256"], "0" * 64)
        self.assertNotEqual(doc["prepare_sha256"], "")
        validated = auth.validate_authorize(raw, _prepare_raw())
        self.assertEqual(validated["authorize"]["prepare_sha256"], PREPARE_DIGEST)

    def test_authorize_v0_has_no_host_path_or_timestamp(self):
        raw = AUTHORIZE_PATH.read_text(encoding="utf-8")
        for marker in (
            "/Users/", "/home/", "/private/tmp/", "/var/folders/",
            "timestamp", "built_at", "elapsed", "mtime", "host_path",
        ):
            self.assertNotIn(marker, raw, marker)


class ValidatorBites(unittest.TestCase):
    def test_extra_or_missing_key_is_refused(self):
        raw = _prepare_raw()
        extra = _authorize_doc(raw, execution={"commit": "x"})
        with self.assertRaises(auth.AuthorizeError) as ctx:
            auth.validate_authorize(_dump(extra), raw)
        self.assertIn("exact keys", str(ctx.exception).lower())
        missing = _authorize_doc(raw)
        del missing["prepare_sha256"]
        with self.assertRaises(auth.AuthorizeError):
            auth.validate_authorize(_dump(missing), raw)

    def test_empty_wrong_or_other_file_prepare_hash_is_refused(self):
        raw = _prepare_raw()
        empty = _authorize_doc(raw, prepare_sha256="")
        with self.assertRaises(auth.AuthorizeError):
            auth.validate_authorize(_dump(empty), raw)
        wrong = _authorize_doc(raw, prepare_sha256="ab" * 32)
        with self.assertRaises(auth.AuthorizeError):
            auth.validate_authorize(_dump(wrong), raw)
        other = (PREREG / "sites.json").read_bytes()
        other_hash = _authorize_doc(raw, prepare_sha256=hashlib.sha256(other).hexdigest())
        with self.assertRaises(auth.AuthorizeError):
            auth.validate_authorize(_dump(other_hash), raw)

    def test_prepare_schema_drift_is_refused(self):
        raw = _prepare_raw()
        drifted = _authorize_doc(raw, prepare_schema="corpus-adequacy.report.v0")
        with self.assertRaises(auth.AuthorizeError) as ctx:
            auth.validate_authorize(_dump(drifted), raw)
        self.assertIn("prepare_schema", str(ctx.exception).lower())
        mutated = _rewrite_prepare(lambda doc: doc.__setitem__("schema", "other.prepare.v0"))
        bound = _authorize_doc(mutated)
        with self.assertRaises(auth.AuthorizeError):
            auth.validate_authorize(_dump(bound), mutated)

    def test_bound_prepare_must_carry_execution_image_and_vendor_toolchain(self):
        cases = (
            (lambda doc: doc["execution"].pop("commit"), "execution"),
            (lambda doc: doc["execution"].pop("content_sha256"), "execution"),
            (lambda doc: doc.pop("execution"), "execution"),
            (lambda doc: doc["image"].pop("id"), "image"),
            (lambda doc: doc["image"].pop("platform"), "image"),
            (lambda doc: doc.pop("image"), "image"),
            (lambda doc: doc.pop("toolchain"), "toolchain"),
            (lambda doc: doc["toolchain"].__setitem__("observation", "host"), "toolchain"),
        )
        for mutator, needle in cases:
            mutated = _rewrite_prepare(mutator)
            bound = _authorize_doc(mutated)
            with self.assertRaises(auth.AuthorizeError, msg=needle) as ctx:
                auth.validate_authorize(_dump(bound), mutated)
            self.assertIn(needle, str(ctx.exception).lower(), needle)

    def test_phase_a_instrument_commit_is_never_execution(self):
        mutated = _rewrite_prepare(lambda doc: doc["execution"].__setitem__(
            "commit", run.PHASE_A_INSTRUMENT_COMMIT))
        bound = _authorize_doc(mutated)
        with self.assertRaises(auth.AuthorizeError) as ctx:
            auth.validate_authorize(_dump(bound), mutated)
        self.assertRegex(str(ctx.exception).lower(), r"instrument|execution|conflat")

    def test_uses_existing_prepare_load_and_schema_constant(self):
        source = Path(auth.__file__).read_text(encoding="utf-8")
        self.assertIn("load_strict", source)
        self.assertIn("PREPARE_SCHEMA", source)
        self.assertIn("emit_prepare_v0", source)
        self.assertIn("PREPARE_KEYS", source)
        self.assertIn("PREPARE_PART_KEYS", source)
        self.assertNotIn("execution_identity", source)
        raw = _prepare_raw()
        doc = auth.load_prepare(raw)
        self.assertEqual(doc["schema"], run.PREPARE_SCHEMA)

    def test_malformed_prepare_with_matching_digest_is_refused(self):
        cases = (
            (lambda doc: doc.__setitem__("phase", "result"), r"phase|canonical|emit"),
            (lambda doc: doc.__setitem__("outcomes", ["fake killed"]), r"exact keys|unknown|outcomes"),
            (lambda doc: doc["materialized"].__setitem__("subject_binary", True),
             r"subject binary"),
            (lambda doc: doc["network"].__setitem__("sealed_oci", "online"), r"network"),
        )
        for mutator, needle in cases:
            mutated = _rewrite_prepare(mutator)
            bound = _authorize_doc(mutated)
            self.assertEqual(
                bound["prepare_sha256"], hashlib.sha256(mutated).hexdigest())
            with self.assertRaises(auth.AuthorizeError, msg=needle) as ctx:
                auth.validate_authorize(_dump(bound), mutated)
            self.assertRegex(str(ctx.exception).lower(), needle, needle)


class SequenceAndDisposition(unittest.TestCase):
    def test_sequence_is_baseline_must_die_control_then_frozen_sites(self):
        steps = auth.required_sequence(_sites())
        self.assertEqual([s["id"] for s in steps], ["baseline", "control", *SEALED_IDS])
        self.assertEqual(steps[0]["kind"], "baseline")
        self.assertEqual(steps[1]["kind"], "must-die")
        self.assertFalse(steps[1]["scored"])
        for step in steps[2:]:
            self.assertEqual(step["operator"], "whole-condition-to-false")
            self.assertEqual(step["kind"], "mutant")

    def test_sequence_reorder_drop_or_add_is_refused(self):
        sites = _sites()
        sites["sites"] = list(reversed(sites["sites"]))
        with self.assertRaises(auth.AuthorizeError):
            auth.required_sequence(sites)
        sites = _sites()
        sites["sites"] = sites["sites"][:-1]
        with self.assertRaises(auth.AuthorizeError):
            auth.required_sequence(sites)
        sites = _sites()
        extra = dict(sites["sites"][-1])
        extra["id"] = "sealed-8"
        sites["sites"] = list(sites["sites"]) + [extra]
        with self.assertRaises(auth.AuthorizeError):
            auth.required_sequence(sites)
        sites = _sites()
        sites["sites"][0]["replacement"] = "true"
        with self.assertRaises(auth.AuthorizeError) as ctx:
            auth.required_sequence(sites)
        self.assertIn("operator", str(ctx.exception).lower())

    def test_baseline_failure_or_control_not_killed_voids(self):
        steps = auth.required_sequence(_sites())
        self.assertEqual(
            auth.classify_observation(steps[0], {"state": "ok", "status": "failed"}),
            "void",
        )
        self.assertEqual(
            auth.classify_observation(
                steps[1], {"state": "ok", "status": "survived", "scored": False}),
            "void",
        )
        self.assertEqual(
            auth.classify_observation(
                steps[1], {"state": "ok", "status": "killed", "scored": True}),
            "void",
        )
        self.assertEqual(
            auth.classify_observation(
                steps[1], {"state": "ok", "status": "killed", "scored": False}),
            "passed",
        )

    def test_wrapper_timeout_signal_output_cap_protocol_are_unproved_never_killed(self):
        step = {"id": "sealed-1", "kind": "mutant", "operator": "whole-condition-to-false"}
        for state in ("wrapper-75", "timeout", "signal", "output-cap", "protocol"):
            got = auth.classify_observation(step, {"state": state, "status": "killed"})
            self.assertEqual(got, "unproved", state)
            self.assertNotEqual(got, "killed")

    def test_baseline_and_control_unproved_states_are_void(self):
        steps = auth.required_sequence(_sites())
        for state in ("wrapper-75", "timeout", "signal", "output-cap", "protocol"):
            self.assertEqual(
                auth.classify_observation(steps[0], {"state": state, "status": "passed"}),
                "void",
                state,
            )
            self.assertEqual(
                auth.classify_observation(
                    steps[1], {"state": state, "status": "killed", "scored": False}),
                "void",
                state,
            )

    def test_authorized_sequence_pins_kinds_operator_and_scored(self):
        steps = auth.required_sequence(_sites())
        pinned = auth.require_authorized_sequence(steps)
        self.assertEqual(pinned[0], {"id": "baseline", "kind": "baseline", "scored": False})
        self.assertEqual(pinned[1], {"id": "control", "kind": "must-die", "scored": False})
        for step in pinned[2:]:
            self.assertEqual(step["kind"], "mutant")
            self.assertEqual(step["operator"], "whole-condition-to-false")
            self.assertNotEqual(step.get("scored"), False)

    def test_missing_state_is_incomplete_void_or_unproved(self):
        steps = auth.required_sequence(_sites())
        self.assertEqual(
            auth.classify_observation(steps[0], {"status": "passed"}),
            "void",
        )
        self.assertEqual(
            auth.classify_observation(steps[1], {"status": "killed", "scored": False}),
            "void",
        )
        self.assertEqual(
            auth.classify_observation(steps[2], {"status": "killed"}),
            "unproved",
        )

    def test_baseline_or_control_scored_zero_is_refused(self):
        steps = list(auth.required_sequence(_sites()))
        steps[0] = dict(steps[0], scored=0)
        with self.assertRaises(auth.AuthorizeError):
            auth.require_authorized_sequence(steps)
        steps = list(auth.required_sequence(_sites()))
        steps[1] = dict(steps[1], scored=0)
        with self.assertRaises(auth.AuthorizeError):
            auth.require_authorized_sequence(steps)

    def test_extra_key_or_explicit_mutant_scored_is_refused(self):
        steps = list(auth.required_sequence(_sites()))
        steps[0] = dict(steps[0], operator=auth.GO_RUN_OPERATOR)
        with self.assertRaises(auth.AuthorizeError):
            auth.require_authorized_sequence(steps)
        for scored in (True, "banana", 1, None):
            steps = list(auth.required_sequence(_sites()))
            steps[2] = dict(steps[2], scored=scored)
            with self.assertRaises(auth.AuthorizeError, msg=repr(scored)):
                auth.require_authorized_sequence(steps)

    def test_removing_exact_key_check_from_sequence_validator_bites(self):
        src = inspect.getsource(auth.require_authorized_sequence)
        self.assertTrue("_exact(" in src or "exact_object(" in src, src)
        self.assertIn("set(", inspect.getsource(common.exact_object))

    def test_right_ids_with_wrong_kind_or_operator_are_refused(self):
        steps = list(auth.required_sequence(_sites()))
        steps[0] = dict(steps[0], kind="mutant")
        with self.assertRaises(auth.AuthorizeError):
            auth.require_authorized_sequence(steps)
        steps = list(auth.required_sequence(_sites()))
        steps[2] = dict(steps[2], operator="flip-to-true")
        with self.assertRaises(auth.AuthorizeError):
            auth.require_authorized_sequence(steps)
        steps = list(auth.required_sequence(_sites()))
        steps[1] = dict(steps[1], scored=True)
        with self.assertRaises(auth.AuthorizeError):
            auth.require_authorized_sequence(steps)

    def test_unknown_state_with_status_killed_is_never_killed(self):
        step = {"id": "sealed-1", "kind": "mutant", "operator": "whole-condition-to-false"}
        got = auth.classify_observation(step, {"state": "mystery", "status": "killed"})
        self.assertIn(got, ("unproved", "void"))
        self.assertNotEqual(got, "killed")

    def test_unknown_mutant_status_is_never_returned_as_killed(self):
        step = {"id": "sealed-1", "kind": "mutant", "operator": "whole-condition-to-false"}
        got = auth.classify_observation(step, {"status": "banana"})
        self.assertIn(got, ("unproved", "void"))
        self.assertNotEqual(got, "banana")
        self.assertNotEqual(got, "killed")

    def test_unknown_baseline_or_control_status_voids_never_killed(self):
        steps = auth.required_sequence(_sites())
        self.assertEqual(
            auth.classify_observation(steps[0], {"status": "killed"}),
            "void",
        )
        self.assertEqual(
            auth.classify_observation(steps[1], {"state": "mystery", "status": "killed", "scored": False}),
            "void",
        )


class PublicNonClaims(unittest.TestCase):
    def test_removing_any_non_claim_from_code_tests_or_docs_fails(self):
        texts = {
            "code": Path(auth.__file__).read_text(encoding="utf-8"),
            "tests": Path(__file__).read_text(encoding="utf-8"),
            "docs": DOCS_PATH.read_text(encoding="utf-8"),
        }
        for phrase in NON_CLAIM_PHRASES:
            for where, text in texts.items():
                self.assertIn(phrase, text, "%s missing %s" % (where, phrase))
        self.assertEqual(tuple(auth.NON_CLAIMS), NON_CLAIM_PHRASES)


class FrozenSitesPin(unittest.TestCase):
    def test_sequence_is_bound_to_frozen_sites_digest(self):
        raw = (PREREG / "sites.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), SITES_DIGEST)
        loaded = auth.load_frozen_sites(PREREG)
        self.assertEqual([s["id"] for s in loaded["sites"]], list(SEALED_IDS))


if __name__ == "__main__":
    unittest.main()
