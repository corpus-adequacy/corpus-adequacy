"""A fake kernel for fake Docker transports (#197).

A real kernel holds what `docker create` asked for, so the fake one derives every read-back file
from the create argv. A test that needs the kernel to disagree says so with an override.
The open-files row is the real kernel's own `/proc/<pid>/limits` layout, from
tests/fixtures/kernel-readback-v0/proc-limits, with only the two values changed.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_LIMITS = (ROOT / "tests" / "fixtures" / "kernel-readback-v0" / "proc-limits").read_bytes()
_READBACK_PATHS = {
    "/sys/fs/cgroup/memory.max": "memory.max",
    "/sys/fs/cgroup/memory.swap.max": "memory.swap.max",
    "/sys/fs/cgroup/pids.max": "pids.max",
    "/sys/fs/cgroup/cpu.max": "cpu.max",
    "/proc/1/limits": "limits",
    # The pids witness's second hold (#197 part 3): the ready file, then the refusal counter.
    "/tmp/.corpus-adequacy-witness-ready": "ready",
    "/sys/fs/cgroup/pids.events": "pids.events",
}


def _flag(argv, name):
    index = argv.index(name)
    return argv[index + 1]


def _bytes(value: str) -> int:
    return 4 * 2 ** 30 if value == "4g" else int(value)


def kernel_files_for(argv) -> dict:
    """What the kernel would hold for a container created with this argv."""
    memory = _bytes(_flag(argv, "--memory"))
    swap = _bytes(_flag(argv, "--memory-swap"))
    files = {
        "memory.max": b"%d\n" % memory,
        "memory.swap.max": b"%d\n" % (swap - memory),
        "pids.max": b"%s\n" % _flag(argv, "--pids-limit").encode("ascii"),
        # A container that never reached its limit. A witness test overrides it.
        "pids.events": b"max 0\n",
    }
    if "--cpu-period" in argv:
        files["cpu.max"] = b"%s %s\n" % (_flag(argv, "--cpu-quota").encode("ascii"),
                                         _flag(argv, "--cpu-period").encode("ascii"))
    soft, hard = "unlimited", "unlimited"
    for index, token in enumerate(argv):
        if token == "--ulimit" and argv[index + 1].startswith("nofile="):
            soft, hard = argv[index + 1][len("nofile="):].split(":")
    row = ("Max open files".ljust(25) + " " + soft.ljust(20) + " " + hard.ljust(20)
           + " files     ").encode("ascii")
    lines = [row if line.startswith(b"Max open files") else line
             for line in _LIMITS.split(b"\n")]
    files["limits"] = b"\n".join(lines)
    return files


RELEASE_PATH = "/tmp/.corpus-adequacy-readback-release"


class FakeKernelMixin:
    """Adds the three read-back operations to a fake transport that records `created`.

    A real wrapper that holds for a read-back does not exit until it is released, so a fake
    whose create argv asks for the hold must not let `start` return before `release`. Call
    `await_release_if_held()` at the top of the fake's `start`. The wait is capped, so a test
    that never releases fails instead of hanging.
    """

    kernel_overrides: dict = {}
    reads: list
    released: list
    hold_wait_seconds = 5.0

    def _release_event(self):
        import threading
        event = getattr(self, "_released_event", None)
        if event is None:
            event = self._released_event = threading.Event()
        return event

    def held(self) -> bool:
        return bool(self.created) and any(RELEASE_PATH in token for token in self.created[-1])

    def await_release_if_held(self) -> bool:
        """True if the fake container was released, or never held. False is the real wrapper's
        hold timing out: the caller returns the `readback-hold` stage code, as the wrapper would."""
        if not self.held():
            return True
        return self._release_event().wait(self.hold_wait_seconds)

    def running(self, name) -> bool:
        return True

    def exec_read(self, name, path):
        self.reads = getattr(self, "reads", []) + [path]
        key = _READBACK_PATHS[path]
        overrides = getattr(self, "kernel_overrides", {}) or {}
        if key in overrides:
            return overrides[key]
        return kernel_files_for(self.created[-1]).get(key)

    release_succeeds = True

    def release(self, name, path) -> bool:
        self.released = getattr(self, "released", []) + [path]
        if self.release_succeeds:
            self._release_event().set()
        return self.release_succeeds
