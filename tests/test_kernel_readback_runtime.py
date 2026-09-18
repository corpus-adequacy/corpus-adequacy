#!/usr/bin/env python3
"""The live kernel read-back: hold, read, release, and envelope v3 (#197 part 2).

Every test drives a fake transport whose fake kernel holds what `docker create` asked for, and
whose fake container, like the real wrapper, does not exit until it is released. Nothing here
starts a container.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "measurements"), str(Path(__file__).resolve().parent)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import aee_checker_sealed_candidate as cand  # noqa: E402
import bounded_run as br  # noqa: E402
import contained_oci as contained  # noqa: E402
import corpus_adequacy as ca  # noqa: E402
import effective_envelope as env  # noqa: E402
import kernel_readback as kr  # noqa: E402
from kernel_fixtures import kernel_files_for  # noqa: E402
from test_aee_checker_sealed_candidate import (  # noqa: E402
    A2_BINDING,
    ObservingTransport,
    _mounts,
    _observed_inspect,
    _prepare_raw,
)

V1 = "contained-oci-v1"
PROFILE = contained.CANDIDATE_RESOURCE_PROFILE_V2


class Ordered(ObservingTransport):
    """Records every call in order across both threads."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.log = []

    def start(self, name, deadline_seconds=None):
        self.log.append("start")
        result = super().start(name, deadline_seconds)
        self.log.append("start-returned")
        return result

    def exec_read(self, name, path):
        self.log.append("read")
        return super().exec_read(name, path)

    def release(self, name, path):
        self.log.append("release")
        return super().release(name, path)


def _run(transport):
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        return cand.run_sealed_candidate(
            prepare_raw=_prepare_raw(PROFILE), mounts=_mounts(Path(d)),
            execution_profile=V1, transport=transport, binding=A2_BINDING)


class HoldReadRelease(unittest.TestCase):
    def test_every_file_is_read_before_the_release_and_the_run_ends_after_it(self):
        transport = Ordered(inspect=_observed_inspect(PROFILE))
        _run(transport)
        reads = [i for i, entry in enumerate(transport.log) if entry == "read"]
        self.assertEqual(len(reads), len(kr.READBACK_PATHS))
        release = transport.log.index("release")
        self.assertTrue(all(i < release for i in reads))
        self.assertLess(release, transport.log.index("start-returned"))
        self.assertEqual(transport.released, [kr.RELEASE_PATH])

    def test_a_verified_run_records_v3_with_the_kernels_own_values(self):
        completed = _run(ObservingTransport(inspect=_observed_inspect(PROFILE)))
        record = completed.envelope_record
        self.assertEqual(record["schema"], env.ENVELOPE_SCHEMA_V3)
        self.assertEqual(record["envelope_status"], "verified", record["unverified_field"])
        self.assertEqual(record["effective"]["kernel"], kr.expected_readback(PROFILE))
        self.assertEqual(record["effective"]["kernel"]["memory_swap_max"], 0)

    def test_a_kernel_that_disagrees_leaves_the_envelope_unverified_and_names_the_field(self):
        for key, raw, field in (("pids.max", b"max\n", "readback_mismatch:pids_max"),
                                ("cpu.max", b"50000 100000\n", "readback_mismatch:cpu_max"),
                                ("memory.max", None, "readback_unreadable:memory_max")):
            with self.subTest(file=key):
                transport = ObservingTransport(inspect=_observed_inspect(PROFILE),
                                               kernel_overrides={key: raw})
                record = _run(transport).envelope_record
                self.assertEqual(record["envelope_status"], "unverified")
                self.assertEqual(record["unverified_field"], field)
                self.assertEqual(record["publication_permission"], "withheld")

    def test_a_failed_read_still_releases_so_the_run_completes_and_is_judged(self):
        class Broken(ObservingTransport):
            def exec_read(self, name, path):
                return None

        transport = Broken(inspect=_observed_inspect(PROFILE))
        completed = _run(transport)
        self.assertEqual(transport.released, [kr.RELEASE_PATH])
        self.assertEqual(completed.envelope_record["candidate_outcome"], "completed")
        self.assertEqual(completed.envelope_record["unverified_field"],
                         "readback_unreadable:memory_max")

    def test_a_container_that_never_runs_is_released_and_nothing_is_read(self):
        class NeverRunning(ObservingTransport):
            def running(self, name):
                return False

        saved = contained.READBACK_RUNNING_POLLS
        contained.READBACK_RUNNING_POLLS = 3
        try:
            transport = NeverRunning(inspect=_observed_inspect(PROFILE))
            record = _run(transport).envelope_record
        finally:
            contained.READBACK_RUNNING_POLLS = saved
        self.assertEqual(getattr(transport, "reads", []), [])
        self.assertEqual(transport.released, [kr.RELEASE_PATH])
        self.assertEqual(record["envelope_status"], "unverified")

    def test_an_attach_that_times_out_is_still_released_and_is_a_timeout(self):
        transport = ObservingTransport(inspect=_observed_inspect(PROFILE), timeout=True)
        record = _run(transport).envelope_record
        self.assertEqual(transport.released, [kr.RELEASE_PATH])
        self.assertEqual(record["candidate_outcome"], "timeout")

    def test_an_output_cap_in_the_attach_thread_is_raised_on_the_caller(self):
        transport = ObservingTransport(inspect=_observed_inspect(PROFILE),
                                       output_too_large=True)
        record = _run(transport).envelope_record
        self.assertEqual(record["candidate_outcome"], "output-cap")


class TheWrapperHold(unittest.TestCase):
    def test_the_hold_comes_first_and_only_when_asked(self):
        held = cand.candidate_script(cand.DEFAULT_EXECUTION_CONTRACT, readback_hold=True)
        plain = cand.candidate_script(cand.DEFAULT_EXECUTION_CONTRACT)
        self.assertEqual(plain, cand.CANDIDATE_SCRIPT)
        self.assertNotIn(kr.RELEASE_PATH, plain)
        self.assertIn(kr.RELEASE_PATH, held)
        self.assertLess(held.index(kr.RELEASE_PATH), held.index("test -d /input/vectors"))
        self.assertIn("candidate_stage %d" % cand.wrapper_stage_returncode("readback-hold"),
                      held)

    def test_only_a_v1_recorded_run_asks_for_the_hold(self):
        for profile, resource, held in (("contained-oci-v0", contained.CANDIDATE_RESOURCE_PROFILE,
                                         False),
                                        (V1, PROFILE, True)):
            with self.subTest(profile=profile):
                import tempfile
                transport = ObservingTransport(inspect=_observed_inspect(resource))
                with tempfile.TemporaryDirectory() as d:
                    cand.run_sealed_candidate(
                        prepare_raw=_prepare_raw(resource), mounts=_mounts(Path(d)),
                        execution_profile=profile, transport=transport, binding=A2_BINDING)
                argv = transport.created[0]
                self.assertEqual(any(kr.RELEASE_PATH in token for token in argv), held)

    def test_a_hold_nobody_released_is_a_named_unproved_reason(self):
        code = cand.wrapper_stage_returncode("readback-hold")
        self.assertEqual(code, 82)
        self.assertIn("candidate-readback-hold", ca.CLOSED_UNPROVED_REASONS)
        self.assertEqual(ca.sanitize_unproved_reason("candidate-readback-hold"),
                         "candidate-readback-hold")


class EnvelopeV3(unittest.TestCase):
    def _record(self, **changes):
        completed = _run(ObservingTransport(inspect=_observed_inspect(PROFILE)))
        record = dict(completed.envelope_record)
        record.update(changes)
        return record

    def test_a_v3_record_round_trips(self):
        record = self._record()
        self.assertEqual(env.validate_envelope_record(record), record)

    def test_a_v2_record_cannot_carry_a_kernel_block(self):
        record = self._record(schema=env.ENVELOPE_SCHEMA_V2)
        with self.assertRaises(env.EnvelopeError):
            env.validate_envelope_record(record)

    def test_a_v3_record_cannot_drop_its_kernel_block(self):
        record = self._record()
        effective = dict(record["effective"])
        del effective["kernel"]
        with self.assertRaises(env.EnvelopeError):
            env.validate_envelope_record(dict(record, effective=effective))

    def test_a_v3_record_whose_kernel_disagrees_cannot_claim_verified(self):
        record = self._record()
        effective = dict(record["effective"])
        effective["kernel"] = dict(effective["kernel"], pids_max=4096)
        with self.assertRaisesRegex(env.EnvelopeError, "readback_mismatch:pids_max"):
            env.validate_envelope_record(dict(record, effective=effective))

    def test_the_fake_kernel_matches_the_real_captured_bytes_for_the_owned_profile(self):
        argv = contained.docker_create_argv(
            image_id="sha256:" + "a" * 64, name="x", mounts={
                key: "/tmp" for key, _dest in cand.CANDIDATE_MOUNT_SPEC},
            command=["-lc", "true"], mount_spec=cand.CANDIDATE_MOUNT_SPEC,
            entrypoint="/bin/sh", resource_profile=PROFILE)
        fake = kernel_files_for(argv)
        real = ROOT / "tests" / "fixtures" / "kernel-readback-v0"
        for key in ("memory.max", "memory.swap.max", "pids.max", "cpu.max"):
            self.assertEqual(fake[key], (real / key).read_bytes(), key)
        self.assertEqual(fake["limits"], (real / "proc-limits").read_bytes())


if __name__ == "__main__":
    unittest.main()
