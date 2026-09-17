#!/usr/bin/env python3
"""Per-attempt attribution in the envelope collection (#185).

The engine names each backend call; an opting-in backend passes that name to the ledger; the v1
collection index carries it with the return code, a run nonce and a member-digest chain; the
hosted layer requires the named steps to be the authorized ones, in authorized order.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.step_fixtures import owned_step, sealed_step  # noqa: E402
from tests.test_contained_hosted_publication import (  # noqa: F401  (module env fixtures)
    BINDINGS,
    _permitted_envelope,
    _write_collection,
    _report,
    _run_ok,
    _write_packet,
    hosted,
    setUpModule,
    tearDownModule,
)
from tests.test_corpus_adequacy import _two_group_process_manifest  # noqa: E402
from tests.test_envelope_collection import _valid_record  # noqa: E402

import corpus_adequacy as ca  # noqa: E402
import envelope_collection as collection  # noqa: E402
from hosted_rail_contract import LEGACY_RAIL, OWNED_V1_RAIL  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
R4_COLLECTION = ROOT / "tests" / "fixtures" / "hosted-r4-terminal" / "effective-envelope"
R4_INDEX_SHA256 = "b899299ac8f8c85f3acda6f739bfe30dbe11aa62fa1f3f5f12f46d3c9764cb61"
NONCE = "0123456789abcdef0123456789abcdef"


def _distinct_record(marker: str) -> dict:
    record = copy.deepcopy(_valid_record())
    record["execution_commit"] = marker * 40
    return record


def _write(dest: Path, rows, *, nonce=NONCE, report_sha256=None) -> Path:
    """rows: (step, state, record_or_exception, returncode)."""
    ledger = collection.Ledger(run_nonce=nonce)
    for step, state, payload, returncode in rows:
        ordinal = ledger.register(step=step)
        if state == collection.RECORDED:
            ledger.recorded(ordinal, payload, returncode=returncode)
        elif state == collection.RAISED:
            ledger.raised(ordinal, payload)
        else:
            ledger.no_envelope(ordinal)
    collection.write_collection(ledger, dest, report_sha256=report_sha256)
    return dest


def _index(dest: Path) -> dict:
    return json.loads((dest / collection.INDEX_FILENAME).read_text(encoding="utf-8"))


def _rewrite_index(dest: Path, index: dict) -> None:
    (dest / collection.INDEX_FILENAME).write_bytes(
        (json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode())


class IndexV1Shape(unittest.TestCase):
    def test_rows_carry_step_returncode_nonce_and_chain(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = _write(Path(raw) / "c", [
                (sealed_step(0), collection.RECORDED, _distinct_record("a"), 0),
                (sealed_step(1), collection.RAISED, "RuntimeError", None),
                (sealed_step(2), collection.NO_ENVELOPE, None, None),
                (sealed_step(3), collection.RECORDED, _distinct_record("b"), 75),
            ])
            index = _index(dest)
            self.assertEqual(index["schema"], collection.COLLECTION_SCHEMA_V1)
            self.assertEqual(index["run_nonce"], NONCE)
            first = index["members"][0]["sha256"]
            self.assertEqual([row["previous_member_sha256"] for row in index["ledger"]],
                             [None, first, first, first])
            self.assertEqual([row["returncode"] for row in index["ledger"]], [0, None, None, 75])
            self.assertEqual([row["step"] for row in index["ledger"]],
                             [sealed_step(i) for i in range(4)])
            self.assertTrue(all(row["run_nonce"] == NONCE for row in index["ledger"]))
            self.assertEqual(index["ledger"][1]["exception_type"], "RuntimeError")
            loaded = collection.load_collection(dest)
            self.assertEqual(len(loaded["members"]), 2)
            self.assertEqual(collection.step_attribution(loaded)[3], {
                "ordinal": 3, "state": "recorded", "step": sealed_step(3), "returncode": 75})

    def test_member_bytes_do_not_change(self):
        with tempfile.TemporaryDirectory() as raw:
            record = _valid_record()
            dest = _write(Path(raw) / "c", [(sealed_step(0), collection.RECORDED, record, 0)])
            member = (dest / "member-0000.json").read_bytes()
            bound = dict(record, report_sha256=None)
            self.assertEqual(member, collection.envelope.encode_envelope(bound))

    def test_a_fresh_ledger_draws_its_own_nonce(self):
        first, second = collection.Ledger(), collection.Ledger()
        self.assertRegex(first.run_nonce, r"^[0-9a-f]{32}$")
        self.assertNotEqual(first.run_nonce, second.run_nonce)
        for bad in ("", "ABCDEF0123456789ABCDEF0123456789", "0" * 31, 7):
            with self.assertRaises(collection.CollectionError):
                collection.Ledger(run_nonce=bad)

    def test_register_and_recorded_judge_step_and_returncode_before_settling(self):
        ledger = collection.Ledger(run_nonce=NONCE)
        for bad in (
            {"kind": "setup", "group": "sealed", "id": None},
            {"kind": "baseline", "group": "sealed", "id": "sealed-1"},
            {"kind": "mutant", "group": None, "id": "sealed-1"},
            {"kind": "mutant", "group": "sealed", "id": "sealed-1", "label": "x"},
            {"kind": "mutant", "group": "sealed", "id": ""},
            {"kind": "mutant", "group": "sealed", "id": "a\nb"},
            ["baseline"],
        ):
            with self.subTest(step=bad):
                with self.assertRaises(collection.CollectionError):
                    ledger.register(step=bad)
        self.assertEqual(ledger.attempts, 0, "a refused step registers nothing")
        ordinal = ledger.register(step=sealed_step(0))
        for bad in (True, "0", 1.0, 2 ** 31):
            with self.subTest(returncode=bad):
                with self.assertRaises(collection.CollectionError):
                    ledger.recorded(ordinal, _valid_record(), returncode=bad)
        ledger.recorded(ordinal, _valid_record(), returncode=-(2 ** 31))


class IndexV1Refusals(unittest.TestCase):
    def _two(self, raw: str) -> Path:
        return _write(Path(raw) / "c", [
            (sealed_step(0), collection.RECORDED, _distinct_record("a"), 0),
            (sealed_step(1), collection.RECORDED, _distinct_record("b"), 0),
        ])

    def _refused(self, dest: Path, reason: str):
        with self.assertRaises(collection.CollectionError) as ctx:
            collection.load_collection(dest)
        self.assertEqual(str(ctx.exception), reason)
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.load_envelope_collection(dest)
        self.assertIn(str(ctx.exception), ("envelope_collection_corrupt", "envelope_corrupt"))

    def test_a_chain_that_does_not_recompute_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = self._two(raw)
            index = _index(dest)
            index["ledger"][1]["previous_member_sha256"] = "f" * 64
            _rewrite_index(dest, index)
            self._refused(dest, "collection chain")

    def test_swapping_two_members_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = self._two(raw)
            a, b = dest / "member-0000.json", dest / "member-0001.json"
            data_a, data_b = a.read_bytes(), b.read_bytes()
            a.write_bytes(data_b)
            b.write_bytes(data_a)
            index = _index(dest)
            index["members"][0]["sha256"], index["members"][1]["sha256"] = (
                index["members"][1]["sha256"], index["members"][0]["sha256"])
            _rewrite_index(dest, index)
            self._refused(dest, "collection chain")

    def test_a_row_nonce_differing_from_the_index_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = self._two(raw)
            index = _index(dest)
            index["ledger"][0]["run_nonce"] = "f" * 32
            _rewrite_index(dest, index)
            self._refused(dest, "collection run nonce mismatch")

    def test_closed_row_and_index_keys(self):
        for mutate, reason in (
            (lambda i: i["ledger"][0].update(host="runner-1"),
             "collection ledger row exact keys missing=[] unknown=['host']"),
            (lambda i: i["ledger"][0].pop("step"),
             "collection ledger row exact keys missing=['step'] unknown=[]"),
            (lambda i: i.pop("run_nonce"),
             "collection index exact keys missing=['run_nonce'] unknown=[]"),
            (lambda i: i["ledger"][0].update(step={"kind": "setup", "group": "sealed",
                                                   "id": None}),
             "collection step kind"),
            (lambda i: i["ledger"][0].update(returncode="0"), "collection returncode"),
            (lambda i: i.update(non_claims=i["non_claims"][:-1]),
             "collection index non-claims"),
            (lambda i: i.update(run_nonce="F" * 32), "collection run nonce"),
        ):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as raw:
                dest = self._two(raw)
                index = _index(dest)
                mutate(index)
                _rewrite_index(dest, index)
                with self.assertRaises(collection.CollectionError) as ctx:
                    collection.load_collection(dest)
                self.assertEqual(str(ctx.exception), reason)

    def test_a_returncode_on_a_raised_row_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = _write(Path(raw) / "c", [
                (sealed_step(0), collection.RAISED, "RuntimeError", None)])
            index = _index(dest)
            index["ledger"][0]["returncode"] = 1
            _rewrite_index(dest, index)
            self._refused(dest, "collection returncode")


class HistoricalV0(unittest.TestCase):
    def test_retained_r4_index_still_loads_as_v0_and_carries_no_attribution(self):
        raw = (R4_COLLECTION / collection.INDEX_FILENAME).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), R4_INDEX_SHA256)
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "c"
            shutil.copytree(R4_COLLECTION, dest)
            loaded = collection.load_collection(dest)
            self.assertEqual(loaded["index"]["schema"], collection.COLLECTION_SCHEMA_V0)
            self.assertEqual(len(loaded["members"]), 9)
            self.assertEqual(collection.step_attribution(loaded), "not-carried")
            hosted.check_collection_steps(loaded, rail=LEGACY_RAIL)  # v0 is not judged

    def test_a_v0_index_with_a_v1_key_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "c"
            shutil.copytree(R4_COLLECTION, dest)
            index = _index(dest)
            index["run_nonce"] = NONCE
            _rewrite_index(dest, index)
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)


class EngineNamesEachCall(unittest.TestCase):
    """The generic engine passes `step` only to a backend that opts in."""

    def _manifest(self, tmp: Path) -> Path:
        path = _two_group_process_manifest(tmp)
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["mutants"]["a"][0]["id"] = "ctl"
        raw["mutants"]["a"][1]["id"] = "a-threshold"
        raw["mutants"]["b"][0]["id"] = "b-outcome"
        raw["mutants"]["b"].insert(0, {"id": "b-missing", "label": "b missing anchor",
                                       "anchor": "NOT IN THE SOURCE",
                                       "replacement": "STILL NOT"})
        path.write_text(json.dumps(raw), encoding="utf-8")
        return path

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_opting_in_backend_sees_every_call_named_and_a_skipped_step_absent(self):
        seen = []

        def backend(m, vectors=None, *, rebuild=True, step):
            seen.append(step)
            return ca._default_execution_backend(m, vectors, rebuild=rebuild)

        backend.accepts_step = True
        with tempfile.TemporaryDirectory() as d:
            path = self._manifest(Path(d))
            report = ca._run_process(ca.load_manifest(path), path,
                                     execution_backend=backend,
                                     execution_profile="trusted-local")
        self.assertEqual(seen, [
            {"kind": "build", "group": None, "id": None},
            {"kind": "baseline", "group": "a", "id": None},
            {"kind": "baseline", "group": "b", "id": None},
            {"kind": "control", "group": "a", "id": "ctl"},
            {"kind": "mutant", "group": "a", "id": "a-threshold"},
            {"kind": "mutant", "group": "b", "id": "b-outcome"},
        ])
        self.assertTrue(any("b missing anchor" in failure for failure in report["failures"]))

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_backend_without_the_declaration_is_called_as_before(self):
        calls = []

        def backend(m, vectors=None, **kwargs):
            calls.append(sorted(kwargs))
            return ca._default_execution_backend(m, vectors, **kwargs)

        with tempfile.TemporaryDirectory() as d:
            path = self._manifest(Path(d))
            ca._run_process(ca.load_manifest(path), path, execution_backend=backend,
                            execution_profile="trusted-local")
        self.assertTrue(calls)
        self.assertTrue(all(kwargs == ["rebuild"] for kwargs in calls))

    def test_a_declaration_other_than_true_is_refused_before_any_call(self):
        for value in ("yes", 1, None, False):
            calls = []

            def backend(m, vectors=None, *, rebuild=True, step=None):
                calls.append(step)
                raise AssertionError("must not be called")

            backend.accepts_step = value
            with self.subTest(value=value), tempfile.TemporaryDirectory() as d:
                path = self._manifest(Path(d))
                with self.assertRaises(ca.ManifestError) as ctx:
                    ca._run_process(ca.load_manifest(path), path, execution_backend=backend,
                                    execution_profile="trusted-local")
                self.assertIn(ca.BACKEND_STEP_ATTRIBUTE, str(ctx.exception))
                self.assertEqual(calls, [])


class HostedStepOrder(unittest.TestCase):
    def _loaded(self, raw: str, steps):
        rows = [(step, collection.RECORDED, _valid_record(), 0) for step in steps]
        dest = _write(Path(raw) / "c", rows)
        return collection.load_collection(dest)

    def test_authorized_order_with_skips_is_accepted_on_both_rails(self):
        with tempfile.TemporaryDirectory() as raw:
            hosted.check_collection_steps(
                self._loaded(raw, [sealed_step(0), sealed_step(1), sealed_step(4)]),
                rail=LEGACY_RAIL)
        with tempfile.TemporaryDirectory() as raw:
            hosted.check_collection_steps(
                self._loaded(raw, [owned_step(i) for i in range(5)]), rail=OWNED_V1_RAIL)

    def test_refusals(self):
        baseline = sealed_step(0)
        for steps, reason in (
            ([sealed_step(1), sealed_step(0)], "collection_step_order"),
            ([sealed_step(1)], "collection_step_order"),
            ([sealed_step(2), sealed_step(3)], "collection_step_order"),
            ([baseline, sealed_step(2), sealed_step(2)], "collection_step_order"),
            ([dict(baseline, group="owned")], "collection_step_group"),
            ([{"kind": "build", "group": "sealed", "id": None}], "collection_step_kind"),
            ([baseline, dict(sealed_step(1), kind="mutant")], "collection_step_kind"),
            ([baseline, dict(sealed_step(2), kind="control")], "collection_step_kind"),
            ([baseline, {"kind": "mutant", "group": "sealed", "id": "sealed-99"}],
             "collection_step_order"),
            ([owned_step(0)], "collection_step_group"),
            ([None], "collection_step_absent"),
        ):
            with self.subTest(reason=reason, steps=steps), \
                    tempfile.TemporaryDirectory() as raw:
                with self.assertRaises(hosted.HostedPublicationError) as ctx:
                    hosted.check_collection_steps(self._loaded(raw, steps), rail=LEGACY_RAIL)
                self.assertEqual(str(ctx.exception), reason)

    def test_gate_refuses_an_out_of_order_collection_through_the_refusal_path(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            (base / "packet").mkdir()
            rels = _write_packet(base / "packet")

            def execute(**kwargs):
                ledger = collection.Ledger()
                ledger.recorded(ledger.register(step=sealed_step(1)),
                                _permitted_envelope(prepare_sha256=rels["prepare_sha256"]))
                report = _report()
                collection.write_collection(
                    ledger, Path(kwargs["envelope_dest"]),
                    report_sha256=hashlib.sha256(ca.encode_report_v0(report)).hexdigest())
                return report

            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(base, "packet", rels, execute=execute)
            self.assertEqual(str(ctx.exception), "collection_step_order")
            out = base / "artifacts"
            setup = json.loads((out / hosted.SETUP_STATUS_FILENAME).read_text())
            self.assertEqual(setup["setup_status"], "refused")
            self.assertFalse((out / hosted.COLLECTION_DIRNAME).exists())

    def test_readback_prints_step_attribution(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            (base / "packet").mkdir()
            rels = _write_packet(base / "packet")
            decision = _run_ok(base, "packet", rels, execute=lambda **kw: _write_collection(
                kw["envelope_dest"], _permitted_envelope(prepare_sha256=rels["prepare_sha256"])))
            self.assertEqual(decision["decision"], "publish")
            out = base / "artifacts"
            loaded = hosted.load_hosted_attempt_artifacts(
                setup_path=out / hosted.SETUP_STATUS_FILENAME,
                candidate_path=out / hosted.CANDIDATE_RESULT_FILENAME,
                rerun_path=out / hosted.RERUN_EVIDENCE_FILENAME,
                collection_dir=out / hosted.COLLECTION_DIRNAME,
                expected_bindings=BINDINGS,
                expected_run_id="1001", expected_run_attempt="1")
            summary = hosted._readback_summary(loaded["projection"])
            self.assertEqual(summary["step_attribution"], [{
                "ordinal": 0, "state": "recorded", "step": sealed_step(0),
                "returncode": None}])


if __name__ == "__main__":
    unittest.main()
