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

    def test_member_byte_ceiling_refuses_at_serialization_before_any_write(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            ledger = collection.Ledger(max_member_bytes=64)
            with self.assertRaises(collection.CollectionError):
                ledger.recorded(ledger.register(), _valid_record())
            self.assertFalse(dest.exists(), "nothing may be written before the size is known good")

    def test_aggregate_ceiling_refuses_the_second_member_and_keeps_the_first(self):
        # The aggregate gate must be reachable. An admission gate that reserved a full
        # per-member ceiling would refuse at register() and this could never fire.
        one = len(collection.envelope.encode_envelope(
            collection.envelope.bind_report(_valid_record(), None)))
        ledger = collection.Ledger(max_member_total_bytes=one + 10)
        ledger.recorded(ledger.register(), _valid_record())
        with self.assertRaises(collection.CollectionError):
            ledger.recorded(ledger.register(), _valid_record())
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "collection"
            collection.write_collection(ledger, dest, report_sha256=None)
            self.assertEqual(len(list(dest.glob("member-*.json"))), 1,
                             "the first member survives the second's refusal")
            self.assertEqual(len(collection.load_collection(dest)["members"]), 1)

    def test_exhausted_budget_refuses_the_next_registration(self):
        one = len(collection.envelope.encode_envelope(
            collection.envelope.bind_report(_valid_record(), None)))
        ledger = collection.Ledger(max_member_total_bytes=one)
        ledger.recorded(ledger.register(), _valid_record())
        with self.assertRaises(collection.CollectionError):
            ledger.register()


if __name__ == "__main__":
    unittest.main()
