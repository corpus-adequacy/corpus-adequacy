#!/usr/bin/env python3
"""#65 inert vs candidate resource contract. Synthetic only. No AEE run."""

from __future__ import annotations

import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import aee_checker_sealed_candidate as cand  # noqa: E402
import aee_checker_sealed_common as common  # noqa: E402
import aee_checker_sealed_oci as oci  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402
from aee_checker_sealed_common import PrepareError  # noqa: E402

PROBE = "sha256:" + ("11" * 32)
TOOLCHAIN = "sha256:" + ("cd" * 32)
IMAGE = TOOLCHAIN


def _mounts(root: Path, *, subject=True):
    names = ("input", "vendor", "tool", "subject") if subject else ("input", "vendor", "tool")
    mounts = {}
    for name in names:
        path = root / name
        path.mkdir()
        mounts[name] = path
    if "input" in mounts:
        vectors = mounts["input"] / "vectors"
        vectors.mkdir()
        (vectors / "MANIFEST.json").write_text(
            json.dumps({"vectors": [{"id": "v1", "file": "v1.json"}]}),
            encoding="utf-8",
        )
    return mounts


def _inspect(dests, *, profile):
    work = "rw,size=%d,nr_inodes=%d,mode=1777" % (
        profile["work_bytes"], profile["work_inodes"])
    tmp = "rw,size=%d,nr_inodes=%d,mode=1777" % (
        profile["tmp_bytes"], profile["tmp_inodes"])
    return {
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Memory": profile["memory_bytes"],
            "MemorySwap": profile["memory_swap_bytes"],
            "PidsLimit": profile["pids"],
            "NetworkMode": "none",
            "Tmpfs": {"/tmp": tmp, "/work": work},
        },
        "Config": {
            "User": "65532:65532",
            "Env": ["CARGO_NET_OFFLINE=true"],
        },
        "Mounts": [
            {"Type": "bind", "Destination": dest, "RW": False}
            for dest in dests
        ],
    }


class RedCandidateCannotUseInert(unittest.TestCase):
    def test_candidate_refuses_prepare_image_id(self):
        with self.assertRaises(PrepareError) as ctx:
            cand.require_candidate_image(
                image_id=PROBE, toolchain_image_id=TOOLCHAIN,
                probe_image_id=PROBE)
        self.assertRegex(str(ctx.exception).lower(), r"inert|probe|toolchain")

    def test_candidate_profile_argv_does_not_reuse_inert_tmpfs(self):
        with tempfile.TemporaryDirectory() as d:
            argv = cand.candidate_create_argv(
                image_id=TOOLCHAIN, name="cand", mounts=_mounts(Path(d)),
                resource_profile=common.CANDIDATE_RESOURCE_PROFILE)
        text = " ".join(argv)
        self.assertNotIn("size=1048576", text)
        self.assertNotIn("nr_inodes=128", text)
        self.assertIn("size=%d" % common.CANDIDATE_RESOURCE_PROFILE["work_bytes"], text)


class InertDefaultByteIdentical(unittest.TestCase):
    def test_omitted_resource_profile_matches_explicit_inert_argv(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d), subject=False)
            omitted = oci.docker_create_argv(
                image_id=PROBE, name="inert", mounts=mounts, command=["ok"])
            explicit = oci.docker_create_argv(
                image_id=PROBE, name="inert", mounts=mounts, command=["ok"],
                resource_profile=common.INERT_RESOURCE_PROFILE)
        self.assertEqual(omitted, explicit)
        text = " ".join(omitted)
        self.assertIn("size=1048576,nr_inodes=128", text)
        self.assertEqual(omitted[omitted.index("--memory") + 1], "4g")
        self.assertEqual(omitted[omitted.index("--memory-swap") + 1], "4g")
        self.assertEqual(omitted[omitted.index("--pids-limit") + 1], "512")

    def test_raising_candidate_work_does_not_rewrite_inert_ceilings(self):
        self.assertEqual(common.TMPFS_BYTES, 1048576)
        self.assertEqual(common.TMPFS_INODES, 128)
        self.assertEqual(common.DECLARED_CEILINGS["deadline_seconds"], 8)
        self.assertEqual(common.INERT_RESOURCE_PROFILE["work_bytes"], 1048576)
        self.assertGreater(
            common.CANDIDATE_RESOURCE_PROFILE["work_bytes"],
            common.INERT_RESOURCE_PROFILE["work_bytes"])
        self.assertNotEqual(
            common.CANDIDATE_RESOURCE_PROFILE, common.INERT_RESOURCE_PROFILE)


class CandidateImageBinding(unittest.TestCase):
    def test_toolchain_image_id_is_accepted(self):
        self.assertEqual(
            cand.require_candidate_image(
                image_id=TOOLCHAIN, toolchain_image_id=TOOLCHAIN,
                probe_image_id=PROBE),
            TOOLCHAIN)

    def test_mutation_selects_prepare_image_id(self):
        with self.assertRaises(PrepareError):
            cand.require_candidate_image(
                image_id=PROBE, toolchain_image_id=TOOLCHAIN,
                probe_image_id=PROBE)


class CandidateDeadline(unittest.TestCase):
    def test_transport_start_uses_profile_deadline_not_sixty(self):
        src = inspect.getsource(cand._DockerTransport.start)
        self.assertNotIn("60", src)
        profile = common.CANDIDATE_RESOURCE_PROFILE
        self.assertEqual(profile["deadline_seconds"], 30)
        self.assertNotEqual(profile["deadline_seconds"], 60)

        class Capture:
            skip_absent = False

            def __init__(self):
                self.deadline = None

            def create(self, argv):
                return None

            def start(self, name, deadline_seconds):
                self.deadline = deadline_seconds
                raise subprocess.TimeoutExpired(["docker", "start", "-a", name], 1)

            def inspect(self, name):
                return _inspect(
                    ("/input", "/vendor", "/tool", "/subject"), profile=profile)

            def remove(self, name):
                return None

            def require_absent(self, name):
                return None

        transport = Capture()
        with tempfile.TemporaryDirectory() as d:
            cand.run_sealed_candidate(
                image_id=TOOLCHAIN, mounts=_mounts(Path(d)),
                resource_profile=profile, transport=transport,
                toolchain_image_id=TOOLCHAIN, probe_image_id=PROBE)
        self.assertEqual(transport.deadline, 30)

    def test_mutation_unbound_or_60_deadline(self):
        src = inspect.getsource(cand._DockerTransport.start)
        self.assertNotIn("60", src)
        self.assertNotIn("None", src.split("deadline")[1][:80] if "deadline" in src else "60")


class CandidateProfileExactKeys(unittest.TestCase):
    def test_fixture_profile_validates(self):
        self.assertEqual(
            common.require_resource_profile(common.CANDIDATE_RESOURCE_PROFILE),
            common.CANDIDATE_RESOURCE_PROFILE)

    def test_mutation_extra_or_missing_candidate_profile_key(self):
        extra = dict(common.CANDIDATE_RESOURCE_PROFILE)
        extra["nice"] = 1
        with self.assertRaises(PrepareError):
            common.require_resource_profile(extra)
        missing = dict(common.CANDIDATE_RESOURCE_PROFILE)
        missing.pop("work_bytes")
        with self.assertRaises(PrepareError):
            common.require_resource_profile(missing)


class InspectFollowsSuppliedProfile(unittest.TestCase):
    def test_candidate_inspect_accepts_fixture_tmpfs(self):
        profile = common.CANDIDATE_RESOURCE_PROFILE
        oci.validate_inspect_contract(
            _inspect(("/input", "/vendor", "/tool"), profile=profile),
            sealed=True, resource_profile=profile)

    def test_mutation_accepts_inspect_payload_that_differs_from_profile(self):
        profile = common.CANDIDATE_RESOURCE_PROFILE
        inspect_doc = _inspect(("/input", "/vendor", "/tool"), profile=profile)
        inspect_doc["HostConfig"]["Tmpfs"]["/work"] = (
            "rw,size=1048576,nr_inodes=128,mode=1777")
        with self.assertRaises(PrepareError):
            oci.validate_inspect_contract(
                inspect_doc, sealed=True, resource_profile=profile)


class InertArgvMutation(unittest.TestCase):
    def test_mutation_changes_inert_default_argv_while_adding_candidate(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d), subject=False)
            argv = oci.docker_create_argv(
                image_id=PROBE, name="inert", mounts=mounts, command=["ok"])
        text = " ".join(argv)
        self.assertIn("--tmpfs /tmp:rw,size=1048576,nr_inodes=128,mode=1777", text)
        self.assertIn("--tmpfs /work:rw,size=1048576,nr_inodes=128,mode=1777", text)
        self.assertIn("--memory 4g", text)


class VersionedPrepare(unittest.TestCase):
    def _v0_parts(self):
        from test_aee_checker_sealed_run import PrepareEvidence
        return PrepareEvidence._parts(self)

class ExecutionIdentity(unittest.TestCase):
    def test_profile_helpers_live_on_listed_execution_paths(self):
        listed = set(run.EXECUTION_PATHS)
        for rel in (
                "measurements/aee_checker_sealed_common.py",
                "measurements/aee_checker_sealed_oci.py",
                "measurements/aee_checker_sealed_candidate.py",
                "measurements/aee_checker_sealed_run.py"):
            self.assertIn(rel, listed)
        stray = REPO_ROOT / "measurements" / "aee_checker_sealed_resources.py"
        self.assertFalse(stray.exists())
        common_src = (REPO_ROOT / "measurements" / "aee_checker_sealed_common.py").read_text(
            encoding="utf-8")
        self.assertIn("CANDIDATE_RESOURCE_PROFILE", common_src)
        self.assertIn("require_resource_profile", common_src)

    def test_mutation_omits_new_runtime_path_from_execution_identity(self):
        self.assertIn(
            "measurements/aee_checker_sealed_common.py", run.EXECUTION_PATHS)
        self.assertIn("require_resource_profile", common.__dict__)


class NoOpControl(unittest.TestCase):
    def test_noop_profile_helpers_stay_green(self):
        self.assertEqual(
            common.require_resource_profile(dict(common.INERT_RESOURCE_PROFILE)),
            common.INERT_RESOURCE_PROFILE)
        self.assertEqual(
            cand.require_candidate_image(
                image_id=TOOLCHAIN, toolchain_image_id=TOOLCHAIN,
                probe_image_id=PROBE),
            TOOLCHAIN)


class MutationReuseInertTmpfs(unittest.TestCase):
    def test_mutation_reuses_inert_tmpfs_limits_for_candidate_work(self):
        with tempfile.TemporaryDirectory() as d:
            argv = cand.candidate_create_argv(
                image_id=TOOLCHAIN, name="cand", mounts=_mounts(Path(d)),
                resource_profile=common.CANDIDATE_RESOURCE_PROFILE)
        work = [item for item in argv if item.startswith("/work:")]
        self.assertEqual(len(work), 1)
        self.assertNotIn("size=1048576", work[0])
        self.assertIn(
            "size=%d" % common.CANDIDATE_RESOURCE_PROFILE["work_bytes"], work[0])


if __name__ == "__main__":
    unittest.main()
