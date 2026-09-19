#!/usr/bin/env python3
"""The pids witness: fork to the limit, then read the kernel's refusal counter (#197 part 3).

Every test drives a fake transport. Its fake container, like the real witness script, holds
twice and does not exit until the second hold is released. Nothing here starts a container.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "measurements"), str(Path(__file__).resolve().parent)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import aee_checker_sealed_candidate as cand  # noqa: E402
import contained_oci as contained  # noqa: E402
import kernel_readback as kr  # noqa: E402
import pids_witness as pw  # noqa: E402
from contained_oci import PrepareError  # noqa: E402
from test_aee_checker_sealed_candidate import (  # noqa: E402
    TOOLCHAIN_IMAGE,
    ObservingTransport,
    _observed_inspect,
)

PROFILE = contained.CANDIDATE_RESOURCE_PROFILE_V2


def _witness_inspect(exit_code=0):
    doc = _observed_inspect(PROFILE)
    doc["Mounts"] = [{"Type": "bind", "Destination": dest, "RW": False}
                     for _key, dest in pw.WITNESS_MOUNT_SPEC]
    doc["State"]["ExitCode"] = exit_code
    return doc


class WitnessTransport(ObservingTransport):
    """A fake witness container: held until the first release, then until the second.

    `ready` says whether the payload ever writes its ready file, and `events` is what the
    kernel's `pids.events` holds by then.
    """

    def __init__(self, *, events=b"max 41\n", ready=True, exit_code=0, **kwargs):
        overrides = dict(kwargs.pop("kernel_overrides", {}))
        overrides.setdefault("pids.events", events)
        overrides.setdefault("ready", b"" if ready else None)
        kwargs.setdefault("stdout", "")
        super().__init__(inspect=_witness_inspect(exit_code), returncode=exit_code,
                         kernel_overrides=overrides, **kwargs)
        self.log = []
        self._events = {kr.RELEASE_PATH: threading.Event(),
                        pw.WITNESS_RELEASE_PATH: threading.Event()}

    def start(self, name, deadline_seconds=None):
        self.log.append("start")
        self.started.append(name)
        for path in (kr.RELEASE_PATH, pw.WITNESS_RELEASE_PATH):
            if not self._events[path].wait(5.0):
                code = (pw.EXIT_READBACK_HOLD if path == kr.RELEASE_PATH
                        else pw.EXIT_WITNESS_HOLD)
                self.log.append("start-returned")
                return subprocess.CompletedProcess(["docker", "start", "-a", name], code,
                                                   self.stdout, "")
        self.log.append("start-returned")
        return subprocess.CompletedProcess(["docker", "start", "-a", name], self.returncode,
                                           self.stdout, "")

    def exec_read(self, name, path):
        self.log.append(("read", path))
        return super().exec_read(name, path)

    def release(self, name, path):
        self.log.append(("release", path))
        self.released = getattr(self, "released", []) + [path]
        self._events[path].set()
        return True


def _witness(transport):
    return pw.run_witness(image_id=TOOLCHAIN_IMAGE, transport=transport)


class TheWitnessScript(unittest.TestCase):
    def setUp(self):
        self.script = pw.witness_script(PROFILE)

    def test_it_holds_for_the_limits_then_forks_then_holds_for_the_counter(self):
        first = self.script.index(kr.RELEASE_PATH)
        fork = self.script.index("sleep %d &" % pw.CHILD_SECONDS)
        ready = self.script.index(pw.READY_PATH)
        second = self.script.index(pw.WITNESS_RELEASE_PATH)
        self.assertLess(first, fork)
        self.assertLess(fork, ready)
        self.assertLess(ready, second)

    def test_it_attempts_twice_the_limit_so_the_kernel_must_refuse(self):
        self.assertIn("-lt %d;" % (2 * PROFILE["pids"]), self.script)

    def test_the_forks_run_in_a_subshell_so_pid_1_survives_the_refusal(self):
        # dash exits at a refused fork. Outside a subshell that would end the container before
        # the host could read the counter.
        self.assertIn("( i=0; while", self.script)
        self.assertIn("done ) 2>/dev/null; sleep %d; wait; " % pw.SETTLE_SECONDS, self.script)

    def test_every_child_is_gone_before_the_ready_file_so_docker_exec_has_room(self):
        self.assertGreater(pw.SETTLE_SECONDS, pw.CHILD_SECONDS)

    def test_a_hold_nobody_releases_exits_with_its_own_code(self):
        self.assertIn("exit %d" % pw.EXIT_READBACK_HOLD, self.script)
        self.assertIn("exit %d" % pw.EXIT_WITNESS_HOLD, self.script)
        self.assertEqual(pw.EXIT_READBACK_HOLD, cand.wrapper_stage_returncode("readback-hold"))

    def test_it_reads_no_candidate_input(self):
        for path in ("/input", "/vendor", "/tool", "/subject", "/work"):
            self.assertNotIn(path, self.script)

    def test_only_a_v2_profile_is_accepted(self):
        with self.assertRaises(PrepareError):
            pw.witness_script(contained.CANDIDATE_RESOURCE_PROFILE)


class TheRun(unittest.TestCase):
    def test_the_counter_is_read_between_the_ready_file_and_the_second_release(self):
        transport = WitnessTransport()
        record = _witness(transport)
        self.assertEqual(record["verdict"], "witnessed", record["unproved_reasons"])
        log = transport.log
        first = log.index(("release", kr.RELEASE_PATH))
        limits = [i for i, e in enumerate(log)
                  if e[0:1] == ("read",) and e[1] in dict(kr.READBACK_PATHS).values()]
        ready = log.index(("read", pw.READY_PATH))
        events = log.index(("read", "/sys/fs/cgroup/pids.events"))
        second = log.index(("release", pw.WITNESS_RELEASE_PATH))
        self.assertEqual(len(limits), len(kr.READBACK_PATHS))
        self.assertTrue(all(i < first for i in limits))
        self.assertLess(first, ready)
        self.assertLess(ready, events)
        self.assertLess(events, second)
        self.assertLess(second, log.index("start-returned"))

    def test_a_witnessed_record_carries_the_kernels_counter_and_its_limits(self):
        record = _witness(WitnessTransport(events=b"max 41\n"))
        self.assertEqual(record["schema"], pw.WITNESS_SCHEMA)
        self.assertEqual(record["pids_events"], {"max": 41})
        self.assertEqual(record["kernel"]["status"], "verified")
        self.assertEqual(record["kernel"]["observed"], kr.expected_readback(PROFILE))
        self.assertEqual(record["exit_code"], 0)
        self.assertEqual(record["unproved_reasons"], [])
        self.assertEqual(record["non_claims"], list(pw.NON_CLAIMS))
        json.dumps(record)  # the record is plain JSON

    def test_a_limit_never_reached_is_unproved_not_a_witness(self):
        record = _witness(WitnessTransport(events=b"max 0\n"))
        self.assertEqual(record["verdict"], "unproved")
        self.assertEqual(record["unproved_reasons"], ["pids-limit-not-reached"])

    def test_unreadable_or_malformed_events_are_unproved_never_assumed(self):
        for raw in (None, b"max\n", b"max -1\n", b"events 3\n"):
            with self.subTest(raw=raw):
                record = _witness(WitnessTransport(events=raw))
                self.assertEqual(record["verdict"], "unproved")
                self.assertEqual(record["pids_events"], None)
                self.assertIn("pids-events-unreadable", record["unproved_reasons"])

    def test_the_payloads_own_output_never_counts(self):
        claim = json.dumps({"verdict": "witnessed", "pids_events": {"max": 999}}) + "\n"
        record = _witness(WitnessTransport(events=b"max 0\n", stdout=claim))
        self.assertEqual(record["verdict"], "unproved")
        self.assertEqual(record["pids_events"], {"max": 0})

    def test_a_ready_file_that_never_appears_reads_no_counter_and_still_releases(self):
        saved = contained.SECOND_HOLD_READY_POLLS
        contained.SECOND_HOLD_READY_POLLS = 3
        try:
            transport = WitnessTransport(ready=False)
            record = _witness(transport)
        finally:
            contained.SECOND_HOLD_READY_POLLS = saved
        self.assertNotIn(("read", "/sys/fs/cgroup/pids.events"), transport.log)
        self.assertEqual(transport.released, [kr.RELEASE_PATH, pw.WITNESS_RELEASE_PATH])
        self.assertIn("pids-events-unreadable", record["unproved_reasons"])

    def test_limits_the_kernel_did_not_hold_make_it_unproved_even_with_a_hit(self):
        record = _witness(WitnessTransport(kernel_overrides={"pids.max": b"1024\n"}))
        self.assertEqual(record["verdict"], "unproved")
        self.assertEqual(record["unproved_reasons"], ["readback:readback_mismatch:pids_max"])

    def test_a_nonzero_exit_is_unproved(self):
        record = _witness(WitnessTransport(exit_code=pw.EXIT_WITNESS_HOLD))
        self.assertEqual(record["unproved_reasons"], ["exit:%d" % pw.EXIT_WITNESS_HOLD])

    def test_a_create_warning_is_unproved(self):
        record = _witness(WitnessTransport(create_warnings=("WARNING: pids limit ignored",)))
        self.assertEqual(record["unproved_reasons"], ["create-warnings"])

    def test_an_unexpected_counter_read_error_still_releases_and_joins(self):
        class Boom(WitnessTransport):
            def exec_read(self, name, path):
                if path == "/sys/fs/cgroup/pids.events":
                    raise RuntimeError("daemon went away")
                return super().exec_read(name, path)

        transport = Boom()
        with self.assertRaises(RuntimeError):
            _witness(transport)
        self.assertIn(("release", pw.WITNESS_RELEASE_PATH), transport.log)
        # The join ran: the attach thread returned before the error reached the caller.
        self.assertIn("start-returned", transport.log)
        self.assertTrue(transport.removed)

    def test_the_create_argv_is_the_sealed_owned_profile_with_one_empty_bind(self):
        transport = WitnessTransport()
        _witness(transport)
        argv = transport.created[0]
        self.assertEqual(argv[argv.index("--pids-limit") + 1], str(PROFILE["pids"]))
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        mounts = [argv[i + 1] for i, t in enumerate(argv) if t == "--mount"]
        self.assertEqual(len(mounts), 1)
        self.assertTrue(mounts[0].endswith("destination=/witness,readonly"))
        self.assertEqual(argv[-3:], [pw.ENTRYPOINT, "-c", pw.witness_script(PROFILE)])


class EveryGateCounts(unittest.TestCase):
    """Each condition of `witnessed`, taken away alone from a run that otherwise witnessed."""

    def _raw(self):
        captured = {}
        real = pw.witness_record

        def keep(raw, **kwargs):
            captured["raw"] = raw
            return real(raw, **kwargs)

        pw.witness_record = keep
        try:
            _witness(WitnessTransport())
        finally:
            pw.witness_record = real
        return captured["raw"]

    def _judge(self, raw):
        return pw.witness_record(raw, image_id=TOOLCHAIN_IMAGE)

    def test_the_untouched_raw_witnessed(self):
        self.assertEqual(self._judge(self._raw())["verdict"], "witnessed")

    def test_a_run_that_did_not_complete_is_unproved(self):
        for state in ("timeout", "output-cap", None):
            with self.subTest(state=state):
                raw = self._raw()
                raw["state"] = state
                record = self._judge(raw)
                self.assertEqual(record["verdict"], "unproved")
                self.assertEqual(record["unproved_reasons"], ["state:%s" % state])

    def test_a_container_that_was_not_removed_is_unproved(self):
        raw = self._raw()
        raw["cleanup"] = "remove-failed"
        record = self._judge(raw)
        self.assertEqual(record["verdict"], "unproved")
        self.assertEqual(record["unproved_reasons"], ["cleanup:remove-failed"])


class TheSecondHold(unittest.TestCase):
    def test_it_needs_the_read_back(self):
        with self.assertRaises(PrepareError):
            contained.run_contained(
                image_id=TOOLCHAIN_IMAGE, mounts={"witness": ROOT},
                command=["-c", "true"], entrypoint="/bin/sh",
                mount_spec=pw.WITNESS_MOUNT_SPEC, resource_profile=PROFILE, sealed=True,
                name_prefix="x-", transport=WitnessTransport(),
                second_hold=(pw.READY_PATH, pw.PIDS_EVENTS_PATHS, pw.WITNESS_RELEASE_PATH))


if __name__ == "__main__":
    unittest.main()
