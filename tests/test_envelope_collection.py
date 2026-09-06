"""Collection of one envelope record per attempted invocation (#106).

RED-first. Every test here drives injected inert backends: no candidate, no Docker, no
container, no score. The single-envelope v0 record, its exact-key validator and the report
bytes are unchanged; this exercises the sibling collection that carries several of them.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import effective_envelope as envelope  # noqa: E402
import envelope_collection as collection  # noqa: E402
import contained_oci as contained  # noqa: E402

IMAGE = "sha256:" + "a" * 64


def _valid_record(*, candidate_outcome="completed", cleanup="removed-and-absent"):
    """A record the pinned builder produces and the pinned validator accepts."""
    profile = contained.CANDIDATE_RESOURCE_PROFILE
    # DEFAULT_MOUNT_SPEC, not CANDIDATE_MOUNT_SPEC: the latter lives in the candidate module,
    # which pulls the sealed adapter. The record only needs a spec the validator accepts.
    spec = contained.DEFAULT_MOUNT_SPEC
    offline = envelope.OFFLINE_ENV_NAME
    image_env = ["IMG_A", "IMG_B"]

    def tmpfs(size, inodes, allow_exec):
        return "size=%d,nr_inodes=%d,mode=1777,nosuid,nodev%s" % (
            size, inodes, ",exec" if allow_exec else ",noexec")

    inspect = {
        "Image": IMAGE,
        "Config": {"Env": ["%s=v" % n for n in image_env + [offline]],
                   "User": envelope.CONTAINED_USER},
        "Mounts": [{"Destination": d, "RW": False, "Type": "bind"} for _s, d in spec],
        "HostConfig": {
            "SecurityOpt": ["no-new-privileges:true"], "Devices": [], "CapAdd": [],
            "CapDrop": ["ALL"], "Memory": profile["memory_bytes"],
            "MemorySwap": profile["memory_swap_bytes"], "NetworkMode": "none",
            "PidMode": "", "PidsLimit": profile["pids"], "Privileged": False,
            "ReadonlyRootfs": True, "UsernsMode": "",
            "Tmpfs": {
                "/tmp": tmpfs(profile["tmp_bytes"], profile["tmp_inodes"], False),
                "/work": tmpfs(profile["work_bytes"], profile["work_inodes"],
                               profile["work_exec"]),
            },
        },
    }
    effective = envelope.project_effective_envelope(
        inspect, image_env_names=image_env, runtime_version="runc version 1.1.12")
    requested = envelope.requested_envelope(
        execution_profile="contained-oci-v0", image_id=IMAGE, mount_spec=spec,
        resource_profile=profile, sealed=True)
    return envelope.build_envelope_record(
        requested=requested, setup_status="ready", envelope_status="verified",
        unverified_field=None, effective=effective, candidate_outcome=candidate_outcome,
        cleanup=cleanup, prepare_sha256="d" * 64, execution_commit="c" * 40,
        report_sha256=None)


def _write_pair(dest, first=None, second=None):
    """Two attempted invocations, both recorded. The default pair is publishable."""
    ledger = collection.Ledger()
    for rec in (first or _valid_record(), second or _valid_record()):
        ordinal = ledger.register()
        ledger.recorded(ordinal, rec)
    collection.write_collection(ledger, dest, report_sha256=None)
    return ledger


class PositivePair(unittest.TestCase):
    def test_two_recorded_members_load_and_permit(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            _write_pair(dest)
            loaded = collection.load_collection(dest)
            self.assertEqual(len(loaded["members"]), 2)
            self.assertEqual(collection.collection_permission(loaded), "permitted")

    def test_equal_outcomes_are_allowed_in_the_positive_pair(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            _write_pair(dest, _valid_record(), _valid_record())
            self.assertEqual(
                collection.collection_permission(collection.load_collection(dest)),
                "permitted")


class PositionalSymmetry(unittest.TestCase):
    """A last-only or first-only implementation must not survive any of these."""

    def _corrupt(self, dest, index_index):
        member = sorted(dest.glob("member-*.json"))[index_index]
        doc = json.loads(member.read_text(encoding="utf-8"))
        doc["publication_permission"] = "permitted"
        doc["cleanup"] = "remove-failed"          # contradicts the derived permission
        raw = (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
        member.write_bytes(raw)
        # Recompute the index digest so this is a SEMANTIC test, not a digest test: the bytes and
        # their recorded digest agree, and only the record's meaning is corrupt.
        index_path = dest / collection.INDEX_FILENAME
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["members"][index_index]["sha256"] = collection.member_digest(raw)
        index_path.write_text(
            json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")

    def test_corrupt_first_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            _write_pair(dest)
            self._corrupt(dest, 0)
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)

    def test_corrupt_last_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            _write_pair(dest)
            self._corrupt(dest, 1)
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)

    def test_withheld_first_withholds(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            _write_pair(dest, _valid_record(cleanup="remove-failed"), _valid_record())
            self.assertEqual(
                collection.collection_permission(collection.load_collection(dest)),
                "withheld")

    def test_withheld_last_withholds(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            _write_pair(dest, _valid_record(), _valid_record(cleanup="remove-failed"))
            self.assertEqual(
                collection.collection_permission(collection.load_collection(dest)),
                "withheld")


class StructuralRefusals(unittest.TestCase):
    def _pair(self, d):
        dest = Path(d) / "collection"
        _write_pair(dest)
        return dest

    def test_missing_member_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._pair(d)
            sorted(dest.glob("member-*.json"))[0].unlink()
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)

    def test_missing_index_is_refused_and_never_falls_back_to_a_singleton(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._pair(d)
            (dest / collection.INDEX_FILENAME).unlink()
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)

    def test_duplicate_ordinal_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._pair(d)
            index = json.loads((dest / collection.INDEX_FILENAME).read_text("utf-8"))
            index["members"][1]["ordinal"] = index["members"][0]["ordinal"]
            (dest / collection.INDEX_FILENAME).write_text(
                json.dumps(index, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)

    def test_reordered_members_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._pair(d)
            index = json.loads((dest / collection.INDEX_FILENAME).read_text("utf-8"))
            index["members"] = list(reversed(index["members"]))
            (dest / collection.INDEX_FILENAME).write_text(
                json.dumps(index, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)

    def test_unreferenced_member_on_disk_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._pair(d)
            (dest / "member-0099.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)

    def test_excess_index_entry_without_a_file_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._pair(d)
            index = json.loads((dest / collection.INDEX_FILENAME).read_text("utf-8"))
            index["members"].append(dict(index["members"][-1], ordinal=2,
                                         relpath="member-0002.json"))
            index["attempts"] = 3
            index["ledger"].append({"ordinal": 2, "state": "recorded"})
            (dest / collection.INDEX_FILENAME).write_text(
                json.dumps(index, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)


class DiagnosticStatesRemainRepresentable(unittest.TestCase):
    """raised and no-envelope must LOAD and be reportable, then withhold."""

    def _one_recorded_one(self, dest, mark):
        ledger = collection.Ledger()
        ledger.recorded(ledger.register(), _valid_record())
        mark(ledger, ledger.register())
        collection.write_collection(ledger, dest, report_sha256=None)

    def test_raised_attempt_loads_and_withholds(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            self._one_recorded_one(dest, lambda l, o: l.raised(o, "RuntimeError"))
            loaded = collection.load_collection(dest)
            self.assertEqual(len(loaded["members"]), 1)
            self.assertEqual(collection.collection_permission(loaded), "withheld")

    def test_no_envelope_attempt_loads_and_withholds_with_its_own_reason(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            self._one_recorded_one(dest, lambda l, o: l.no_envelope(o))
            loaded = collection.load_collection(dest)
            self.assertEqual(collection.collection_permission(loaded), "withheld")
            self.assertNotEqual(
                collection.withheld_reason(loaded),
                collection.withheld_reason({"ledger": [{"ordinal": 0, "state": "raised"}],
                                            "members": []}),
                "no-envelope and raised must not report the same reason")

    def test_raised_state_never_carries_an_exception_message(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            ledger = collection.Ledger()
            ledger.raised(ledger.register(), "RuntimeError")
            collection.write_collection(ledger, dest, report_sha256=None)
            raw = (dest / collection.INDEX_FILENAME).read_text(encoding="utf-8")
            self.assertIn("RuntimeError", raw)
            self.assertNotIn("Traceback", raw)


class ZeroAttempts(unittest.TestCase):
    def test_zero_attempts_refuses_rather_than_succeeding_silently(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            collection.write_collection(collection.Ledger(), dest, report_sha256=None)
            loaded = collection.load_collection(dest)
            self.assertEqual(collection.collection_permission(loaded), "withheld")


class Ceilings(unittest.TestCase):
    def test_count_ceiling_refuses_at_registration_before_the_call(self):
        ledger = collection.Ledger(max_members=2)
        ledger.register()
        ledger.register()
        with self.assertRaises(collection.CollectionError):
            ledger.register()

    def test_member_ceiling_is_judged_on_the_REPORT_BOUND_encoding(self):
        """The bytes that get written are the report-bound ones. Sizing the unbound record
        admitted members the writer then exceeded: 2769 admitted, 2831 written, own reader
        rejected."""
        record = _valid_record()
        unbound = len(collection.envelope.encode_envelope(
            collection.envelope.bind_report(record, None)))
        bound = len(collection.envelope.encode_envelope(
            collection.envelope.bind_report(record, "a" * 64)))
        self.assertGreater(bound, unbound, "binding a report must grow the record")
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            ledger = collection.Ledger(max_member_bytes=unbound)
            ledger.recorded(ledger.register(), record)
            with self.assertRaises(collection.CollectionError):
                collection.write_collection(ledger, dest, report_sha256="a" * 64)
            self.assertEqual(list(dest.glob("member-*.json")) if dest.exists() else [], [],
                             "nothing may be written when the final size is refused")

    def test_preflight_refuses_without_materializing_the_full_encoding(self):
        """Encoder spy, no huge allocation: encode_envelope must never run for a record the
        preflight rejects."""
        calls = []
        original = collection.envelope.encode_envelope

        def spy(record):
            calls.append(record)
            return original(record)

        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            ledger = collection.Ledger(max_member_bytes=64)
            ledger.recorded(ledger.register(), _valid_record())
            collection.envelope.encode_envelope = spy
            try:
                with self.assertRaises(collection.CollectionError):
                    collection.write_collection(ledger, dest, report_sha256=None)
            finally:
                collection.envelope.encode_envelope = original
        self.assertEqual(calls, [],
                         "the full encoding must not be built for a record already over the cap")

    def test_bounded_encoded_size_matches_the_encoder_exactly_when_it_fits(self):
        record = collection.envelope.bind_report(_valid_record(), "a" * 64)
        actual = len(collection.envelope.encode_envelope(record))
        self.assertEqual(collection.bounded_encoded_size(record, actual), actual,
                         "the preflight must be exact, not an estimate")

    def test_aggregate_ceiling_uses_final_sizes_and_keeps_nothing_partial(self):
        record = _valid_record()
        one = len(collection.envelope.encode_envelope(
            collection.envelope.bind_report(record, "a" * 64)))
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            ledger = collection.Ledger(max_member_total_bytes=one + 10)
            ledger.recorded(ledger.register(), record)
            ledger.recorded(ledger.register(), record)
            with self.assertRaises(collection.CollectionError):
                collection.write_collection(ledger, dest, report_sha256="a" * 64)
            self.assertEqual(list(dest.glob("member-*.json")) if dest.exists() else [], [],
                             "the aggregate refusal happens before any write")


def _contradictory_record(**kw):
    """An OBSERVATION the runtime could hand us that the validator must reject.

    Built valid, then contradicted in place: `cleanup` says the removal failed while
    `publication_permission` still claims `permitted`. The builder can never emit this, which is
    the point -- it is what a buggy or hostile producer emits, and the collection's job is to
    carry it faithfully so the reader can refuse it, not to quietly agree with one half.
    """
    record = dict(_valid_record(**kw))
    record["cleanup"] = "remove-failed"
    record["publication_permission"] = "permitted"
    return record


class WriterPreservesObservations(unittest.TestCase):
    """The writer records what was observed; only the reader judges it.

    `bind_report` reconstructs a record from its inputs, which is exactly how
    `validate_envelope_record` detects a contradiction. Writing that reconstruction instead of the
    observation makes the reconstruction trivially agree with the stored bytes and destroys the
    check at the moment of writing.
    """

    def _write_one(self, dest, record):
        ledger = collection.Ledger()
        ledger.recorded(ledger.register(), record)
        collection.write_collection(ledger, dest, report_sha256="b" * 64)

    def test_writer_does_not_normalize_a_contradicted_permission(self):
        observed = _contradictory_record()
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "coll"
            self._write_one(dest, observed)
            member = json.loads(
                (dest / (collection.MEMBER_TEMPLATE % 0)).read_text("utf-8"))
        # Report binding is an authorized field addition, so byte identity with the pre-binding
        # dict is NOT claimed. Every other observed field must survive verbatim.
        self.assertEqual(member["cleanup"], "remove-failed")
        self.assertEqual(
            member["publication_permission"], "permitted",
            "writer rewrote an observed contradiction into an honestly-withheld member")
        self.assertEqual(member["report_sha256"], "b" * 64)

    def test_contradicted_member_is_still_refused_on_read(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "coll"
            self._write_one(dest, _contradictory_record())
            with self.assertRaises(collection.CollectionError) as ctx:
                collection.load_collection(dest)
        self.assertEqual(str(ctx.exception), "collection member semantics")

    def test_contradiction_last_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "coll"
            _write_pair(dest, _valid_record(), _contradictory_record())
            with self.assertRaises(collection.CollectionError) as ctx:
                collection.load_collection(dest)
        self.assertEqual(str(ctx.exception), "collection member semantics")

    def test_contradiction_first_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "coll"
            _write_pair(dest, _contradictory_record(), _valid_record())
            with self.assertRaises(collection.CollectionError) as ctx:
                collection.load_collection(dest)
        self.assertEqual(str(ctx.exception), "collection member semantics")

    def test_an_uncontradicted_withheld_member_still_round_trips(self):
        """Positive control: the refusal must key on the contradiction, not on `withheld`."""
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "coll"
            self._write_one(dest, _valid_record(cleanup="remove-failed"))
            loaded = collection.load_collection(dest)
        self.assertEqual(len(loaded["members"]), 1)
        self.assertEqual(loaded["members"][0]["publication_permission"], "withheld")


class ReportBinding(unittest.TestCase):
    """A coordinator probe found the index carried a report claim nothing checked, and the
    members carried none at all. Only None fixtures were being tested."""

    REPORT = "a" * 64

    def _write(self, dest, report):
        ledger = collection.Ledger()
        for _ in range(2):
            ledger.recorded(ledger.register(), _valid_record())
        collection.write_collection(ledger, dest, report_sha256=report)

    def test_non_null_report_reaches_every_member_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            self._write(dest, self.REPORT)
            loaded = collection.load_collection(dest)
            self.assertEqual(loaded["index"]["report_sha256"], self.REPORT)
            self.assertEqual([m["report_sha256"] for m in loaded["members"]],
                             [self.REPORT, self.REPORT],
                             "every member must be bound to the report, not left None")

    def test_malformed_index_report_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            self._write(dest, self.REPORT)
            index_path = dest / collection.INDEX_FILENAME
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["report_sha256"] = "not-a-digest"
            index_path.write_text(
                json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)

    def test_index_report_that_disagrees_with_members_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            self._write(dest, self.REPORT)
            index_path = dest / collection.INDEX_FILENAME
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["report_sha256"] = "b" * 64      # well-formed, but not what members carry
            index_path.write_text(
                json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)


class AttemptCeilingIsIndependent(unittest.TestCase):
    def test_non_recorded_attempts_cannot_bypass_the_cap(self):
        # 257 attempts that emitted nothing passed a cap of 256 because only members were
        # counted. Permission stayed withheld, so never a false publish -- but the resource
        # contract did not hold on input, which is what this pins.
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            ledger = collection.Ledger(max_members=300)
            for _ in range(257):
                ledger.no_envelope(ledger.register())
            collection.write_collection(ledger, dest, report_sha256=None)
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)          # default cap is 256

    def test_the_cap_still_admits_exactly_its_limit(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            ledger = collection.Ledger(max_members=300)
            for _ in range(256):
                ledger.no_envelope(ledger.register())
            collection.write_collection(ledger, dest, report_sha256=None)
            loaded = collection.load_collection(dest)     # control: 256 is admitted
            self.assertEqual(collection.collection_permission(loaded), "withheld")


class StagedWrite(unittest.TestCase):
    def test_index_ceiling_refuses_before_any_member_is_written(self):
        # The index is built and bounded first, so an index-size refusal leaves nothing behind.
        # An earlier version wrote members first and then claimed that property.
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            ledger = collection.Ledger()
            ledger.recorded(ledger.register(), _valid_record())
            original = collection.MAX_INDEX_BYTES
            try:
                collection.MAX_INDEX_BYTES = 16
                with self.assertRaises(collection.CollectionError):
                    collection.write_collection(ledger, dest, report_sha256=None)
            finally:
                collection.MAX_INDEX_BYTES = original
            self.assertEqual(list(dest.glob("member-*.json")), [],
                             "no member may be written before the index is known to fit")


if __name__ == "__main__":
    unittest.main()


class MalformedMemberBytes(unittest.TestCase):
    def test_oversized_integer_literal_is_a_named_refusal_not_an_escape(self):
        """A >4300-digit integer raises a bare ValueError, not JSONDecodeError. A narrower
        clause lets it escape unmapped -- the defect corpus #116 found at the other loader."""
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            _write_pair(dest)
            member = sorted(dest.glob("member-*.json"))[0]
            raw = ('{"n": ' + "9" * 4400 + "}").encode()
            member.write_bytes(raw)
            index_path = dest / collection.INDEX_FILENAME
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["members"][0]["sha256"] = collection.member_digest(raw)
            index_path.write_text(
                json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8")
            with self.assertRaises(collection.CollectionError):
                collection.load_collection(dest)


class PreflightBoundary(unittest.TestCase):
    def test_the_trailing_newline_is_inside_the_limit_not_after_it(self):
        """bounded_encoded_size({}, 2) returned 3: the newline was added after the check, so a
        record exactly at the boundary passed and then wrote one byte over."""
        exact = len(json.dumps({}, ensure_ascii=False, indent=2, sort_keys=True)) + 1
        self.assertEqual(collection.bounded_encoded_size({}, exact), exact)
        with self.assertRaises(collection.CollectionError):
            collection.bounded_encoded_size({}, exact - 1)

    def test_preflight_matches_the_encoder_including_the_newline(self):
        record = collection.envelope.bind_report(_valid_record(), "a" * 64)
        actual = len(collection.envelope.encode_envelope(record))
        self.assertEqual(collection.bounded_encoded_size(record, actual), actual)
        with self.assertRaises(collection.CollectionError):
            collection.bounded_encoded_size(record, actual - 1)

    def test_a_single_huge_scalar_is_NOT_bounded_and_that_is_stated(self):
        """Documents the real limit rather than overclaiming: iterencode yields one escaped
        string scalar whole, so a single large value is materialized before the cap sees it.
        Small input; no large allocation needed to show the shape."""
        chunks = list(json.JSONEncoder(ensure_ascii=False, indent=2, sort_keys=True)
                      .iterencode({"s": "x" * 64}))
        biggest = max(len(c) for c in chunks)
        self.assertGreaterEqual(biggest, 64,
                                "one scalar arrives as a single chunk, so per-chunk size is "
                                "not bounded by the limit")
