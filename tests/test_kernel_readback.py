#!/usr/bin/env python3
"""Kernel-interface limit read-back, the pure half (#197, part 1 of 4).

The positive cases run on bytes the kernel really returned, captured once inside a container with
the owned resource profile's limits (tests/fixtures/kernel-readback-v0/README.md). Nothing here
starts a container.
"""

from __future__ import annotations

import ast
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "measurements")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import kernel_readback as kr  # noqa: E402
import sealed_measurement_contract as contracts  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "kernel-readback-v0"
PROFILE = json.loads(
    (ROOT / "measurements" / "owned-slice-b-20f6d8b" / "declared" / "prepare.v2.json")
    .read_text(encoding="utf-8"))["candidate_profile"]


def _raw(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _files() -> dict:
    return {"memory.max": _raw("memory.max"), "memory.swap.max": _raw("memory.swap.max"),
            "pids.max": _raw("pids.max"), "cpu.max": _raw("cpu.max"),
            "limits": _raw("proc-limits")}


class TheKernelsOwnBytes(unittest.TestCase):
    def test_each_real_file_parses(self):
        self.assertEqual(kr.parse_limit(_raw("memory.max"), "memory.max"), 4294967296)
        self.assertEqual(kr.parse_limit(_raw("memory.swap.max"), "memory.swap.max"), 0)
        self.assertEqual(kr.parse_limit(_raw("pids.max"), "pids.max"), 512)
        self.assertEqual(kr.parse_cpu_max(_raw("cpu.max")), (100000, 100000))
        self.assertEqual(kr.parse_pids_events(_raw("pids.events")), {"max": 0})
        self.assertEqual(kr.parse_open_files(_raw("proc-limits")), (1024, 1024))

    def test_the_owned_profile_reads_back_verified(self):
        record = kr.readback_record(_files(), PROFILE)
        self.assertEqual(record["status"], "verified")
        self.assertEqual(record["problems"], [])
        self.assertEqual(record["observed"], kr.expected_readback(PROFILE))

    def test_max_and_unlimited_are_kept_as_words_not_numbers(self):
        self.assertEqual(kr.parse_limit(b"max\n", "pids.max"), "max")
        self.assertEqual(kr.parse_cpu_max(b"max 100000\n"), ("max", 100000))
        line = "Max open files".ljust(25) + " " + "unlimited".ljust(20) + " " \
            + "unlimited".ljust(20) + " files     "
        raw = ("Limit".ljust(25) + " Soft Limit           Hard Limit           Units     \n"
               + line + "\n").encode("ascii")
        self.assertEqual(kr.parse_open_files(raw), ("unlimited", "unlimited"))


class WhatTheProfileShouldReadBackAs(unittest.TestCase):
    def test_swap_is_memory_swap_minus_memory(self):
        """Docker's --memory-swap is memory plus swap; cgroup v2 swap.max is swap alone."""
        self.assertEqual(kr.cgroup_v2_swap(4294967296, 4294967296), 0)
        self.assertEqual(kr.cgroup_v2_swap(6 * 2 ** 30, 4 * 2 ** 30), 2 * 2 ** 30)
        for swap, memory in ((2 ** 30, 2 * 2 ** 30), (2 ** 30, 0), (2 ** 30, -1), (-1, 2 ** 30)):
            with self.subTest(swap=swap, memory=memory):
                with self.assertRaises(kr.ReadbackError):
                    kr.cgroup_v2_swap(swap, memory)

    def test_the_cpu_expectation_uses_the_shared_quota_mapping(self):
        expected = kr.expected_readback(PROFILE)
        self.assertEqual(expected["cpu_max"],
                         [kr.contained.cpu_quota_usec(PROFILE), kr.contained.CPU_PERIOD_USEC])

    def test_quota_and_period_are_not_interchangeable(self):
        """At one CPU the two numbers are equal, so only a fractional rate shows their order."""
        half = dict(PROFILE, cpu_rate_millicpu=500)
        self.assertEqual(kr.expected_readback(half)["cpu_max"], [50000, 100000])
        files = dict(_files(), **{"cpu.max": b"50000 100000\n"})
        self.assertEqual(kr.readback_record(files, half)["status"], "verified")
        files = dict(_files(), **{"cpu.max": b"100000 50000\n"})
        self.assertEqual(kr.readback_record(files, half)["problems"],
                         ["readback_mismatch:cpu_max"])

    def test_a_v1_profile_has_no_read_back_expectation(self):
        with self.assertRaises(Exception):
            kr.expected_readback(dict(PROFILE, schema="corpus-adequacy.not-a-profile"))


class ADifferingOrUnreadableValueIsNeverVerified(unittest.TestCase):
    def test_each_differing_field_is_named(self):
        changed = {
            "memory.max": b"4294967295\n", "memory.swap.max": b"4294967296\n",
            "pids.max": b"max\n", "cpu.max": b"200000 100000\n",
        }
        fields = {"memory.max": "memory_max", "memory.swap.max": "memory_swap_max",
                  "pids.max": "pids_max", "cpu.max": "cpu_max"}
        for name, raw in changed.items():
            with self.subTest(file=name):
                record = kr.readback_record(dict(_files(), **{name: raw}), PROFILE)
                self.assertEqual(record["status"], "unverified")
                self.assertEqual(record["problems"], ["readback_mismatch:%s" % fields[name]])

    def test_a_differing_open_file_limit_is_named(self):
        raw = _raw("proc-limits").replace(
            b"Max open files            1024                 1024",
            b"Max open files            1024                 4096")
        record = kr.readback_record(dict(_files(), limits=raw), PROFILE)
        self.assertEqual(record["problems"], ["readback_mismatch:nofile_hard"])

    def test_a_file_that_did_not_read_is_unreadable_not_assumed(self):
        for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max", "limits"):
            with self.subTest(missing=name):
                files = _files()
                del files[name]
                record = kr.readback_record(files, PROFILE)
                self.assertEqual(record["status"], "unverified")
                self.assertTrue(all(p.startswith("readback_unreadable:")
                                    for p in record["problems"]))

    def test_text_not_in_the_kernels_form_is_unreadable_not_a_value(self):
        for raw in (b"", b"512", b" 512\n", b"+512\n", b"-1\n", b"0512\n", b"5e2\n",
                    b"512\n512\n", "٥١٢\n".encode("utf-8"), b"512 \n"):
            with self.subTest(raw=raw):
                record = kr.readback_record(dict(_files(), **{"pids.max": raw}), PROFILE)
                self.assertIn("readback_unreadable:pids_max", record["problems"])

    def test_limits_without_the_kernels_header_is_unreadable(self):
        headerless = b"\n".join(_raw("proc-limits").split(b"\n")[1:])
        record = kr.readback_record(dict(_files(), limits=headerless), PROFILE)
        self.assertIn("readback_unreadable:nofile_soft", record["problems"])

    def test_an_unknown_file_is_refused_rather_than_ignored(self):
        with self.assertRaises(kr.ReadbackError):
            kr.observe(dict(_files(), **{"memory.high": b"max\n"}))

    def test_an_observation_must_carry_exactly_the_closed_fields(self):
        expected = kr.expected_readback(PROFILE)
        with self.assertRaises(kr.ReadbackError):
            kr.compare(dict(expected, extra=1), expected)
        partial = dict(expected)
        del partial["pids_max"]
        with self.assertRaises(kr.ReadbackError):
            kr.compare(partial, expected)


class APidsWitness(unittest.TestCase):
    def test_completing_without_a_refused_fork_is_unproved_not_a_witness(self):
        self.assertEqual(kr.classify_pids_witness(_raw("pids.events")), "unproved")

    def test_a_refused_fork_counted_by_the_kernel_is_a_witness(self):
        self.assertEqual(kr.classify_pids_witness(b"max 3\n"), "witnessed")
        # No released kernel writes max.imposed; it only shows an extra key is tolerated.
        self.assertEqual(kr.classify_pids_witness(b"max 1\nmax.imposed 1\n"), "witnessed")

    def test_unreadable_events_are_unproved(self):
        for raw in (b"", b"max\n", b"max 1", b"imposed 1\n", b"max 1\nmax 2\n", b"MAX 1\n"):
            with self.subTest(raw=raw):
                self.assertEqual(kr.classify_pids_witness(raw), "unproved")


class InsideTheExecutionIdentity(unittest.TestCase):
    def test_every_contract_executes_this_module(self):
        """Part 2 wired the read into the runtime, so the module is in every contract's
        identity and changing it needs a fresh PREPARE (#197)."""
        found = [(name, value) for name, value in vars(contracts).items()
                 if isinstance(value, contracts.SealedMeasurementContract)]
        self.assertGreaterEqual(len(found), 3)
        for name, contract in found:
            with self.subTest(contract=name):
                self.assertIn("measurements/kernel_readback.py", contract.execution_paths)

    def test_the_module_reads_nothing_itself(self):
        tree = ast.parse((ROOT / "measurements" / "kernel_readback.py").read_text(
            encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertEqual(imported, {"__future__", "re", "sys", "pathlib", "contained_oci"})
        source = (ROOT / "measurements" / "kernel_readback.py").read_text(encoding="utf-8")
        for call in ("open(", "read_bytes(", "read_text(", "subprocess"):
            self.assertNotIn(call, source)


if __name__ == "__main__":
    unittest.main()
