#!/usr/bin/env python3
"""Behavioural tests for the shared child-output ceiling. Standard library only.

A fast child can finish a write far above the cap between 250 ms polls when
stdout/stderr land on TemporaryFile objects. These tests require continuous
pipe drains, one combined counter, and a process-group kill that still works
after the leader has exited. Windows has no process-tree claim here.
Source-string mutations are supplementary; the cases above are the contract.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import bounded_run as br  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = (REPO_ROOT / "bounded_run.py").read_text(encoding="utf-8")
TEST_CAP = 64 * 1024
BURST = 256 * 1024
# One completed crossing write, then hold: a larger write is still in
# progress when the parent closes the pipe, and SIGPIPE kills the
# descendant even without a group kill.
HOLD = TEST_CAP + 64 * 1024
POSIX = hasattr(os, "killpg") and hasattr(os, "setsid")
DESCENDANT = """\
import os, signal, sys, time
from pathlib import Path
signal.signal(signal.SIGHUP, signal.SIG_IGN)
pid_path = Path(sys.argv[1])
n = int(sys.argv[2])
if os.fork() == 0:
    pid_path.write_text(str(os.getpid()))
    sys.stdout.buffer.write(b'x' * n)
    sys.stdout.buffer.flush()
    time.sleep(30)
    os._exit(0)
for _ in range(200):
    if pid_path.exists() and pid_path.stat().st_size:
        break
    time.sleep(0.01)
os._exit(0)
"""


class _CountPipe:
    def __init__(self, raw, counter):
        self._raw = raw
        self._counter = counter

    def read(self, n=-1):
        data = self._raw.read(n)
        self._counter[0] += len(data)
        return data

    def close(self):
        return self._raw.close()

    def __getattr__(self, name):
        return getattr(self._raw, name)


def _probe(tmp: Path, body: str, *args: str) -> list[str]:
    script = tmp / "probe.py"
    script.write_text(body, encoding="utf-8")
    return [sys.executable, str(script), *args]


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _reap_pid(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        return


def _mutated_run(test: unittest.TestCase, old: str, new: str):
    test.assertEqual(SOURCE.count(old), 1, old)
    ns: dict = {}
    exec(compile(SOURCE.replace(old, new, 1), "<mutated-bounded-run>", "exec"), ns)
    ns["OUTPUT_CAP_BYTES"] = TEST_CAP
    return ns["_run_capped"]


class _WithTestCap(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(br, "OUTPUT_CAP_BYTES", TEST_CAP)
        patcher.start()
        self.addCleanup(patcher.stop)


class ContinuousCap(_WithTestCap):
    def test_fast_burst_uses_pipes_and_stays_inside_the_read_margin(self):
        seen = {}
        pulled = [0]
        real = subprocess.Popen

        def spy(*args, **kwargs):
            seen["stdout"] = kwargs.get("stdout")
            seen["stderr"] = kwargs.get("stderr")
            proc = real(*args, **kwargs)
            if proc.stdout is not None:
                proc.stdout = _CountPipe(proc.stdout, pulled)
            if proc.stderr is not None:
                proc.stderr = _CountPipe(proc.stderr, pulled)
            return proc

        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            cmd = _probe(tmp, "import sys\nsys.stdout.buffer.write(b'x' * %d)\n" % BURST)
            popen = mock.patch.object(subprocess, "Popen", side_effect=spy)
            popen.start()
            self.addCleanup(popen.stop)
            with self.assertRaises(br._OutputTooLarge):
                br._run_capped(cmd, tmp, 5)
        self.assertIs(seen.get("stdout"), subprocess.PIPE)
        self.assertIs(seen.get("stderr"), subprocess.PIPE)
        self.assertTrue(hasattr(br, "READ_CHUNK_BYTES"))
        self.assertEqual(br.READ_CHUNK_BYTES, 64 * 1024)
        self.assertGreater(pulled[0], TEST_CAP)
        self.assertLessEqual(pulled[0], TEST_CAP + br.READ_CHUNK_BYTES)

    def test_interleaved_stdout_and_stderr_share_one_combined_cap(self):
        body = (
            "import sys\n"
            "for _ in range(8):\n"
            "    sys.stdout.buffer.write(b'O' * 10000)\n"
            "    sys.stderr.buffer.write(b'E' * 10000)\n"
            "    sys.stdout.buffer.flush()\n"
            "    sys.stderr.buffer.flush()\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with self.assertRaises(br._OutputTooLarge):
                br._run_capped(_probe(tmp, body), tmp, 5)

    def test_stderr_only_burst_is_still_capped(self):
        body = "import sys\nsys.stderr.buffer.write(b'E' * %d)\n" % BURST
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with self.assertRaises(br._OutputTooLarge):
                br._run_capped(_probe(tmp, body), tmp, 5)

    def test_timeout_stays_timeout_expired(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            with self.assertRaises(subprocess.TimeoutExpired):
                br._run_capped(_probe(tmp, "import time\ntime.sleep(30)\n"), tmp, 1)

    def test_normal_completion_keeps_rc0_and_both_streams(self):
        body = (
            "import sys\n"
            "sys.stdout.write('hello-out\\n')\n"
            "sys.stderr.write('hello-err\\n')\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            done = br._run_capped(_probe(tmp, body), tmp, 5)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "hello-out\n")
        self.assertEqual(done.stderr, "hello-err\n")

    def test_utf8_replacement_is_deterministic_after_chunk_joins(self):
        chunk = mock.patch.object(br, "READ_CHUNK_BYTES", 1, create=True)
        chunk.start()
        self.addCleanup(chunk.stop)
        body = "import sys\nsys.stdout.buffer.write(b'ok\\xc3\\xa9\\xff')\n"
        texts = []
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            cmd = _probe(tmp, body)
            for _ in range(2):
                done = br._run_capped(cmd, tmp, 5)
                texts.append(done.stdout)
        self.assertEqual(texts[0], texts[1])
        self.assertEqual(texts[0], "oké\ufffd")
        self.assertEqual(done.returncode, 0)


class DescendantPipes(_WithTestCap):
    """Leader-exit must not lose the captured POSIX group."""

    def test_descendant_holding_pipes_is_group_killed(self):
        if not POSIX:
            self.skipTest(
                "Windows has no process-group claim; direct-child kill only"
            )
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            pid_path = tmp / "desc.pid"
            cmd = _probe(tmp, DESCENDANT, str(pid_path), str(HOLD))
            try:
                with self.assertRaises(br._OutputTooLarge):
                    br._run_capped(cmd, tmp, 5)
                pid = int(pid_path.read_text())
                deadline = time.monotonic() + 2
                while _pid_alive(pid) and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertFalse(_pid_alive(pid), "descendant still held the pipes")
            finally:
                if pid_path.exists() and pid_path.stat().st_size:
                    _reap_pid(int(pid_path.read_text()))


class Mutations(unittest.TestCase):
    """Source-string edits that must bite. Not a substitute for the cases above."""

    def test_removing_the_cap_check_lets_a_burst_complete(self):
        run = _mutated_run(self, "if total > cap:", "if False and total > cap:")
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            cmd = _probe(tmp, "import sys\nsys.stdout.buffer.write(b'x' * %d)\n" % BURST)
            done = run(cmd, tmp, 5)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(len(done.stdout), BURST)

    def test_counting_only_stdout_misses_stderr_overflow(self):
        run = _mutated_run(
            self, "total += len(data)", "total += len(data) if which == 1 else 0"
        )
        body = "import sys\nsys.stderr.buffer.write(b'E' * %d)\n" % BURST
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            done = run(_probe(tmp, body), tmp, 5)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(len(done.stderr), BURST)

    def test_leader_only_kill_leaves_a_posix_descendant(self):
        if not POSIX:
            self.skipTest(
                "Windows has no process-group claim; direct-child kill only"
            )
        run = _mutated_run(self, "os.killpg(pgid, signal.SIGKILL)", "proc.kill()")
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            pid_path = tmp / "desc.pid"
            finished = []

            def go():
                try:
                    finished.append(run(_probe(tmp, DESCENDANT, str(pid_path), str(HOLD)), tmp, 5))
                except Exception as exc:  # noqa: BLE001 - mutation outcome
                    finished.append(exc)

            worker = threading.Thread(target=go)
            worker.start()
            try:
                deadline = time.monotonic() + 2
                while (not pid_path.exists() or not pid_path.stat().st_size) and (
                    time.monotonic() < deadline
                ):
                    time.sleep(0.05)
                pid = int(pid_path.read_text())
                worker.join(timeout=1.0)
                self.assertTrue(
                    _pid_alive(pid),
                    "leader-only kill must leave the bursting descendant",
                )
            finally:
                if pid_path.exists() and pid_path.stat().st_size:
                    _reap_pid(int(pid_path.read_text()))
                worker.join(timeout=2)

    def test_removing_timeout_lets_a_sleeper_finish(self):
        run = _mutated_run(
            self,
            "if time.monotonic() > deadline:",
            "if False and time.monotonic() > deadline:",
        )
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            done = run(_probe(tmp, "import time\ntime.sleep(1.2)\n"), tmp, 1)
        self.assertEqual(done.returncode, 0)

    def test_swapping_normal_streams_breaks_rc0_payload(self):
        run = _mutated_run(
            self,
            "cmd, proc.returncode, stdout_text, stderr_text",
            "cmd, proc.returncode, stderr_text, stdout_text",
        )
        body = (
            "import sys\n"
            "sys.stdout.write('hello-out\\n')\n"
            "sys.stderr.write('hello-err\\n')\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            done = run(_probe(tmp, body), tmp, 5)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "hello-err\n")
        self.assertEqual(done.stderr, "hello-out\n")


if __name__ == "__main__":
    unittest.main(verbosity=1)
