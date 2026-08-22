#!/usr/bin/env python3
"""Synthetic sealed-candidate backend tests. No live checker/corpus/#211."""

from __future__ import annotations

import importlib.util
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
import aee_checker_sealed_oci as oci  # noqa: E402
import corpus_adequacy as ca  # noqa: E402

from aee_checker_sealed_common import PrepareError  # noqa: E402

IMAGE = "sha256:" + ("ab" * 32)
POLICY = {"accepted_exit_codes": [0], "unproved_exit_codes": [75]}
INNER = {
    "verdict": "valid",
    "result": "ok",
    "tiersWithPinnedKey": ["t"],
    "tiersWithoutKey": [],
}
PROJECTION = (
    "verdict", "result", "tiersWithPinnedKey", "tiersWithoutKey",
)


def _mounts(root: Path, *, subject=True):
    names = ("input", "vendor", "tool", "subject") if subject else ("input", "vendor", "tool")
    mounts = {}
    for name in names:
        path = root / name
        path.mkdir()
        mounts[name] = path
    return mounts


def _classify(completed):
    return ca.classify(
        completed.returncode,
        POLICY["accepted_exit_codes"],
        POLICY["unproved_exit_codes"],
    )


def _inspect(dests):
    return {
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Memory": 4294967296,
            "MemorySwap": 4294967296,
            "PidsLimit": 512,
            "NetworkMode": "none",
            "Tmpfs": {
                "/tmp": "rw,size=1048576,nr_inodes=128,mode=1777",
                "/work": "rw,size=1048576,nr_inodes=128,mode=1777",
            },
        },
        "Config": {"User": "65532:65532", "Env": ["CARGO_NET_OFFLINE=true"]},
        "Mounts": [
            {"Type": "bind", "Destination": dest, "RW": False}
            for dest in dests
        ],
    }


class FakeTransport:
    def __init__(
            self, *, returncode=0, stdout="", inspect=None,
            timeout=False, output_cap=False, skip_absent=False,
            leave_present=False, fail_create=False, fail_create_after=False):
        self.returncode = returncode
        self.stdout = stdout
        self.inspect_doc = inspect
        self.timeout = timeout
        self.output_cap = output_cap
        self.skip_absent = skip_absent
        self.leave_present = leave_present
        self.fail_create = fail_create
        self.fail_create_after = fail_create_after
        self.created = []
        self.removed = []
        self.absent_checked = []
        self.started = []

    def create(self, argv):
        self.created.append(list(argv))
        if self.fail_create:
            raise PrepareError("partial create")
        if self.fail_create_after:
            raise PrepareError("partial create")

    def start(self, name):
        self.started.append(name)
        if self.timeout:
            raise subprocess.TimeoutExpired(["docker", "start", "-a", name], 1)
        if self.output_cap:
            raise Exception("output_cap")
        return subprocess.CompletedProcess(
            ["docker", "start", "-a", name],
            self.returncode,
            self.stdout,
            "",
        )

    def inspect(self, name):
        return self.inspect_doc

    def remove(self, name):
        self.removed.append(name)

    def require_absent(self, name):
        self.absent_checked.append(name)
        if self.leave_present:
            raise PrepareError("container still present: %s" % name)


def _load_mutated(text: str, tmp: Path):
    path = tmp / "mut_candidate.py"
    path.write_text(text)
    spec = importlib.util.spec_from_file_location("mut_candidate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InertByteCompat(unittest.TestCase):
    def test_default_create_argv_stays_probe_and_three_mounts(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d), subject=False)
            argv = oci.docker_create_argv(
                image_id=IMAGE, name="inert", mounts=mounts, command=["ok"])
        self.assertEqual(argv[argv.index(IMAGE) + 1], "/probe")
        self.assertEqual(argv[argv.index(IMAGE) + 2], "ok")
        text = " ".join(argv)
        self.assertIn("destination=/input,readonly", text)
        self.assertIn("destination=/vendor,readonly", text)
        self.assertIn("destination=/tool,readonly", text)
        self.assertNotIn("/subject", text)
        self.assertNotIn("/bin/sh", text)

    def test_explicit_default_entrypoint_matches_omitted(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d), subject=False)
            omitted = oci.docker_create_argv(
                image_id=IMAGE, name="inert", mounts=mounts, command=["ok"])
            explicit = oci.docker_create_argv(
                image_id=IMAGE, name="inert", mounts=mounts, command=["ok"],
                entrypoint="/probe")
        self.assertEqual(omitted, explicit)


class CandidateArgv(unittest.TestCase):
    def test_candidate_selects_bin_sh_lc_and_subject_readonly(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            argv = cand.candidate_create_argv(
                image_id=IMAGE, name="cand", mounts=mounts)
        idx = argv.index(IMAGE)
        self.assertEqual(argv[idx + 1], "/bin/sh")
        self.assertEqual(argv[idx + 2], "-lc")
        script = argv[idx + 3]
        self.assertIn("cargo build --locked --offline", script)
        self.assertIn("/input", script)
        self.assertIn("/vendor", script)
        self.assertIn("/tool/checker", script)
        self.assertIn("/subject", script)
        self.assertNotIn("cargo test", script)
        text = " ".join(argv)
        for dest in ("/input", "/vendor", "/tool", "/subject"):
            self.assertIn("destination=%s,readonly" % dest, text)
        self.assertNotIn("/probe", text)
        self.assertNotIn("/result", text)

    def test_readonly_drop_mutation_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            argv = cand.candidate_create_argv(
                image_id=IMAGE, name="cand", mounts=mounts)
        for token in argv:
            if token.startswith("type=bind,"):
                self.assertTrue(token.endswith(",readonly"), token)

    def test_explicit_entrypoint_omitted_falls_back_to_probe(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            forgotten = oci.docker_create_argv(
                image_id=IMAGE, name="cand", mounts=mounts,
                command=["-lc", cand.CANDIDATE_SCRIPT],
                mount_spec=cand.CANDIDATE_MOUNT_SPEC)
        self.assertEqual(forgotten[forgotten.index(IMAGE) + 1], "/probe")
        self.assertNotEqual(forgotten[forgotten.index(IMAGE) + 1], "/bin/sh")

    def test_writable_result_bind_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            mounts = _mounts(root)
            mounts["result"] = root / "result"
            mounts["result"].mkdir()
            with self.assertRaises(PrepareError):
                cand.candidate_create_argv(
                    image_id=IMAGE, name="cand", mounts=mounts)
            inspect = _inspect(("/input", "/vendor", "/tool", "/subject", "/result"))
            inspect["Mounts"][-1]["RW"] = True
            with self.assertRaises(PrepareError):
                oci.validate_inspect_contract(
                    inspect, sealed=True, mount_spec=cand.CANDIDATE_MOUNT_SPEC)


class InnerNormalize(unittest.TestCase):
    def test_rc0_and_rc1_parse_projection_once(self):
        for rc in (0, 1):
            completed = cand.normalize_inner_event(
                returncode=rc, stdout=json.dumps(INNER))
            self.assertEqual(completed.returncode, 0)
            outer = json.loads(completed.stdout)
            self.assertEqual(set(outer), set(PROJECTION))
            for key in PROJECTION:
                self.assertEqual(outer[key], INNER[key])
            self.assertEqual(_classify(completed), "ok")

    def test_empty_or_missing_projection_is_unproved(self):
        for raw in ("{}", json.dumps({"verdict": "valid"}), json.dumps({
                "verdict": "valid", "result": "ok",
                "tiersWithPinnedKey": [], "extra": 1})):
            completed = cand.normalize_inner_event(returncode=0, stdout=raw)
            self.assertEqual(completed.returncode, 75)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(_classify(completed), "unproved")

    def test_outer_is_distinct_and_not_double_parsed(self):
        inner = dict(INNER)
        inner["reason"] = "prose"
        completed = cand.normalize_inner_event(
            returncode=0, stdout=json.dumps(inner))
        outer = json.loads(completed.stdout)
        self.assertNotEqual(outer, inner)
        self.assertNotIn("reason", outer)
        self.assertEqual(outer["verdict"], "valid")

    def test_rc2_passthrough_is_unexpected_exit_then_killed(self):
        leaked = subprocess.CompletedProcess(["x"], 2, json.dumps(INNER), "")
        kind = _classify(leaked)
        self.assertEqual(kind, "unexpected-exit")
        self.assertIn(kind, ca.TERMINATED_KINDS)
        normalized = cand.normalize_inner_event(returncode=2, stdout=json.dumps(INNER))
        self.assertEqual(normalized.returncode, 75)
        self.assertEqual(normalized.stdout, "")
        self.assertEqual(_classify(normalized), "unproved")
        m = {
            "accepted_exit_codes": [0],
            "unproved_exit_codes": [75],
            "outcome_from": "verdict",
        }
        _failed, _diag, kind = ca.child_outcome(
            m, subprocess.CompletedProcess([], 75, json.dumps(INNER), ""))
        self.assertEqual(kind, "unproved")
        self.assertIsNone(_failed)

    def test_compile_fail_does_not_score_killed(self):
        completed = cand.normalize_inner_event(returncode=2, stdout="error: fail")
        self.assertEqual(_classify(completed), "unproved")
        self.assertEqual(completed.stdout, "")

    def test_stdout_prefix_is_unproved_without_inner_parse(self):
        inner = "noise\n" + json.dumps(INNER)
        completed = cand.normalize_inner_event(returncode=0, stdout=inner)
        self.assertEqual(completed.returncode, 75)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(_classify(completed), "unproved")

    def test_signal_and_timeout_normalize_to_unproved(self):
        for rc, stdout in ((-9, "killed"), (None, ""), (3, "{}")):
            completed = cand.normalize_inner_event(returncode=rc, stdout=stdout)
            self.assertEqual(completed.returncode, 75)
            self.assertEqual(_classify(completed), "unproved")

    def test_copy_mutation_drops_rc1_acceptance(self):
        src = Path(cand.__file__).read_text()
        mutated = src.replace("COMPLETE_RETURNCODES = (0, 1)", "COMPLETE_RETURNCODES = (0,)")
        self.assertNotEqual(src, mutated)
        with tempfile.TemporaryDirectory() as d:
            module = _load_mutated(mutated, Path(d))
            completed = module.normalize_inner_event(
                returncode=1, stdout=json.dumps(INNER))
        self.assertEqual(completed.returncode, 75)


class SealedLifecycle(unittest.TestCase):
    def test_absence_proof_runs_on_success_and_error(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            transport = FakeTransport(
                stdout=json.dumps(INNER),
                inspect=_inspect(("/input", "/vendor", "/tool", "/subject")),
            )
            cand.run_sealed_candidate(
                image_id=IMAGE, mounts=mounts, transport=transport)
            self.assertEqual(len(transport.removed), 1)
            self.assertEqual(len(transport.absent_checked), 1)

            broken = FakeTransport(
                returncode=2, stdout="fail",
                inspect=_inspect(("/input", "/vendor", "/tool", "/subject")),
            )
            cand.run_sealed_candidate(
                image_id=IMAGE, mounts=mounts, transport=broken)
            self.assertEqual(len(broken.removed), 1)
            self.assertEqual(len(broken.absent_checked), 1)

    def test_partial_create_still_removes_then_proves_absent(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            transport = FakeTransport(fail_create=True)
            with self.assertRaises(PrepareError) as ctx:
                cand.run_sealed_candidate(
                    image_id=IMAGE, mounts=mounts, transport=transport)
            self.assertEqual(str(ctx.exception), "partial create")
            self.assertEqual(len(transport.removed), 1)
            self.assertEqual(len(transport.absent_checked), 1)

            present = FakeTransport(fail_create=True, leave_present=True)
            with self.assertRaises(PrepareError) as ctx:
                cand.run_sealed_candidate(
                    image_id=IMAGE, mounts=mounts, transport=present)
            self.assertIn("still present", str(ctx.exception))

    def test_absence_proof_skipped_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            transport = FakeTransport(
                stdout=json.dumps(INNER),
                inspect=_inspect(("/input", "/vendor", "/tool", "/subject")),
                skip_absent=True,
            )
            with self.assertRaises(PrepareError):
                cand.run_sealed_candidate(
                    image_id=IMAGE, mounts=mounts, transport=transport)

    def test_noop_control_stays_green(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = _mounts(Path(d))
            transport = FakeTransport(
                stdout=json.dumps(INNER),
                inspect=_inspect(("/input", "/vendor", "/tool", "/subject")),
            )
            completed = cand.run_sealed_candidate(
                image_id=IMAGE, mounts=mounts, transport=transport)
        self.assertEqual(_classify(completed), "ok")
        self.assertEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
