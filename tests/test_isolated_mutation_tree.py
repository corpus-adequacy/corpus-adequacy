#!/usr/bin/env python3
"""Isolated working-tree copy for process/batch mutation.

SIGKILL of the tool cannot run Python finally, so a leftover copy may remain
under temp and is not auto-deleted. Tests may reap only children of a recorded
tool PID — never other processes. The external SIGKILL test gives the child its
own empty TMPDIR and watches for a new prefix directory there.
"""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import corpus_adequacy as ca  # noqa: E402
import isolated_tree as iso  # noqa: E402


def _batch_python() -> str:
    return sys.executable


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=iso-test",
         "-c", "user.email=iso-test@example.com", *args],
        check=check, capture_output=True, text=True,
    )


def _write_batch_corpus(tmp: Path, *, one_mutant: bool = False,
                        sleep_mutant: bool = False) -> Path:
    """Batch fixture similar to tests/test_corpus_adequacy.py BatchRunner."""
    (tmp / "check.py").write_text(
        "import json, sys\n"
        "doc = json.load(open(sys.argv[1]))\n"
        "fails = [c['id'] for c in doc['cases'] if c['n'] > 10]\n"
        "print(json.dumps({'ok': not fails, 'failures': fails}))\n",
        encoding="utf-8",
    )
    (tmp / "vectors.json").write_text(json.dumps({"cases": [
        {"id": "c1", "n": 1}, {"id": "c2", "n": 2}]}), encoding="utf-8")
    if sleep_mutant:
        threshold = {
            "label": "threshold",
            "anchor": "import json, sys\n",
            "replacement": (
                "import json, sys\n"
                "import time; time.sleep(60)  # MUTANT_VISIBLE\n"
            ),
        }
    else:
        threshold = {
            "label": "threshold",
            "anchor": "c['n'] > 10",
            "replacement": "c['n'] > 0  # MUTANT_VISIBLE",
        }
    mutants = [threshold]
    if not one_mutant:
        mutants.append({
            "label": "CONTROL", "control": True,
            "anchor": "'ok': not fails", "replacement": "'ok': 'MOVED'",
        })
    raw = {
        "schema": ca.SCHEMA, "runner": "batch", "repo_root": ".",
        "implementation_sources": ["check.py"],
        "entrypoint_command": [_batch_python(), "check.py", "vectors.json"],
        "outcome_from": ["ok", "failures"], "vectors": "vectors.json",
        "id_key": "vector_id", "default_group": "g",
        "mutants": {"g": mutants},
    }
    manifest = tmp / "m.json"
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    return manifest


def _assert_lock_releasable(test: unittest.TestCase, repo_root: Path) -> None:
    second = ca._TreeLock(repo_root)
    try:
        second.__enter__()
    finally:
        if second.held:
            second.__exit__()


def _reap_tool_group(pid: int) -> None:
    """Reap only the recorded tool PID and descendants of that session.

    SIGKILL of the tool cannot run Python finally, so a mutant entrypoint
    started as a child of that PID may still be alive.
    """
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _prefix_dirs(tmp: Path, repo: Path) -> list[Path]:
    prefix = iso._tree_prefix(repo)
    found = []
    if not tmp.is_dir():
        return found
    for child in tmp.iterdir():
        if child.name.startswith(prefix) and child.is_dir() and not child.is_symlink():
            found.append(child)
    return found


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


class IsolatedTreeCaps(unittest.TestCase):
    def test_ceilings_are_owned_and_are_not_the_output_cap(self):
        self.assertEqual(iso.MATERIALIZATION_CAP_BYTES, 64 * 1024 * 1024)
        self.assertGreater(iso.MATERIALIZATION_CAP_FILES, 0)
        import bounded_run as br
        self.assertNotEqual(iso.MATERIALIZATION_CAP_BYTES, br.OUTPUT_CAP_BYTES)
        src = Path(iso.__file__).read_text(encoding="utf-8")
        self.assertNotIn("OUTPUT_CAP_BYTES", src)
        self.assertNotIn("bounded_run", src)

    def test_no_stable_pointer_or_cross_run_forget(self):
        src = Path(iso.__file__).read_text(encoding="utf-8")
        self.assertNotIn("isolated_tree_pointer", src)
        self.assertNotIn("_forget_previous_root", src)
        self.assertNotIn("_write_pointer_atomic", src)
        self.assertFalse(hasattr(iso, "isolated_tree_pointer"))

    def test_copy_refuses_without_nofollow_before_creating_the_destination(self):
        """Fail-closed: O_NOFOLLOW=None raises before the destination exists."""
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "src.bin"
            dest = Path(d) / "out.bin"
            src.write_bytes(b"ABC")
            with mock.patch.object(iso.os, "O_NOFOLLOW", None, create=True):
                with self.assertRaises(iso.IsolationError) as cm:
                    iso._copy_regular_bounded(src, dest, 0, 64)
            self.assertFalse(dest.exists())
            self.assertIn("o_nofollow", str(cm.exception).lower())


@unittest.skipIf(
    not hasattr(os, "O_NOFOLLOW"),
    "process/batch refuse before materialize when O_NOFOLLOW is absent",
)
class MaterializeHelper(unittest.TestCase):
    def test_dirty_bytes_appear_in_the_copy_not_head(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "check.py").write_text("CLEAN = 1\n", encoding="utf-8")
            _git(root, "init")
            _git(root, "add", "check.py")
            _git(root, "commit", "-m", "clean")
            (root / "check.py").write_text("CLEAN = 1\nDIRTY_DECLARED\n", encoding="utf-8")
            tree = iso.IsolatedMutationTree(root)
            try:
                isolated = tree.materialize()
                copied = (isolated / "check.py").read_bytes()
                self.assertIn(b"DIRTY_DECLARED", copied)
                head = subprocess.run(
                    ["git", "-C", str(root), "show", "HEAD:check.py"],
                    capture_output=True, check=True)
                self.assertNotIn(b"DIRTY_DECLARED", head.stdout)
                self.assertEqual(copied, (root / "check.py").read_bytes())
                self.assertFalse((isolated / ".git").exists())
                self.assertEqual(tree.root, isolated)
                self.assertFalse(_under(isolated, root))
            finally:
                tree.cleanup()

    def test_every_symlink_is_refused_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            root = tmp / "repo"
            root.mkdir()
            outside = tmp / "outside.txt"
            outside.write_text("OUTSIDE_SECRET\n", encoding="utf-8")
            before = outside.read_bytes()
            (root / "keep.py").write_text("ok\n", encoding="utf-8")
            (root / "target.py").write_text("TARGET\n", encoding="utf-8")
            for name, dest in (("escape", outside), ("contained", root / "target.py")):
                with self.subTest(name=name):
                    link = root / "link"
                    if link.exists() or link.is_symlink():
                        link.unlink()
                    link.symlink_to(dest)
                    tree = iso.IsolatedMutationTree(root)
                    with self.assertRaises(iso.IsolationError) as cm:
                        tree.materialize()
                    self.assertIn("symlink", str(cm.exception).lower())
                    self.assertEqual(outside.read_bytes(), before)
                    self.assertEqual((root / "keep.py").read_text(encoding="utf-8"), "ok\n")
                    tree.cleanup()
                    link.unlink()

    def test_symlink_escape_is_refused_and_outside_bytes_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            root = tmp / "repo"
            root.mkdir()
            outside = tmp / "outside.txt"
            outside.write_text("OUTSIDE_SECRET\n", encoding="utf-8")
            before = outside.read_bytes()
            (root / "keep.py").write_text("ok\n", encoding="utf-8")
            (root / "escape").symlink_to(outside)
            tree = iso.IsolatedMutationTree(root)
            with self.assertRaises(iso.IsolationError) as cm:
                tree.materialize()
            self.assertIn("symlink", str(cm.exception).lower())
            self.assertEqual(outside.read_bytes(), before)
            self.assertEqual((root / "keep.py").read_text(encoding="utf-8"), "ok\n")
            tree.cleanup()

    def test_tiny_cap_refuses_and_leaves_original_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            payload = b"X" * 200
            (root / "big.bin").write_bytes(payload)
            before = (root / "big.bin").read_bytes()
            tree = iso.IsolatedMutationTree(root)
            with self.assertRaises(iso.IsolationError) as cm:
                tree.materialize(cap=50)
            self.assertIn("50", str(cm.exception))
            self.assertTrue("ceiling" in str(cm.exception).lower()
                            or "cap" in str(cm.exception).lower())
            self.assertEqual((root / "big.bin").read_bytes(), before)
            tree.cleanup()

    def test_missing_original_root_is_refused(self):
        missing = Path(tempfile.gettempdir()) / "iso-missing-root-does-not-exist"
        tree = iso.IsolatedMutationTree(missing)
        with self.assertRaises(iso.IsolationError) as cm:
            tree.materialize()
        self.assertTrue("missing" in str(cm.exception).lower()
                        or "not" in str(cm.exception).lower())
        tree.cleanup()

    def test_each_materialize_uses_a_new_root_outside_the_checkout(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.py").write_text("A\n", encoding="utf-8")
            first = iso.IsolatedMutationTree(root)
            second = iso.IsolatedMutationTree(root)
            try:
                p1 = first.materialize()
                p1_res = p1.resolve()
                sys_tmp = Path(tempfile.gettempdir()).resolve()
                self.assertTrue(_under(p1_res, sys_tmp))
                self.assertFalse(_under(p1_res, root))
                p2 = second.materialize()
                self.assertNotEqual(p1_res, p2.resolve())
                self.assertFalse(_under(p2.resolve(), root))
            finally:
                first.cleanup()
                second.cleanup()

    def test_file_cap_refuses_mid_walk_and_leaves_original(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for i in range(3):
                (root / ("f%d.txt" % i)).write_text("x\n", encoding="utf-8")
            snapshot = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
            tree = iso.IsolatedMutationTree(root)
            with self.assertRaises(iso.IsolationError) as cm:
                tree.materialize(file_cap=2)
            self.assertIn("2", str(cm.exception))
            now = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
            self.assertEqual(now, snapshot)
            tree.cleanup()

    def test_regular_git_worktree_file_is_not_copied(self):
        """Measured: a regular .git file (worktree pointer) was copied."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.py").write_text("A\n", encoding="utf-8")
            gitfile = root / ".git"
            gitfile.write_text("gitdir: /somewhere/else\n", encoding="utf-8")
            tree = iso.IsolatedMutationTree(root)
            try:
                isolated = tree.materialize()
                self.assertTrue((isolated / "a.py").is_file())
                self.assertFalse((isolated / ".git").exists())
            finally:
                tree.cleanup()

    def test_empty_dirs_count_against_the_entry_cap(self):
        """Measured: 20 empty dirs passed file_cap=2."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "keep.py").write_text("ok\n", encoding="utf-8")
            for i in range(20):
                (root / ("empty%d" % i)).mkdir()
            snapshot = sorted(p.name for p in root.iterdir())
            tree = iso.IsolatedMutationTree(root)
            with self.assertRaises(iso.IsolationError) as cm:
                tree.materialize(file_cap=2)
            self.assertIn("2", str(cm.exception))
            self.assertEqual(sorted(p.name for p in root.iterdir()), snapshot)
            tree.cleanup()

    def test_short_os_write_still_copies_every_byte(self):
        """Measured: os.write reported 8 bytes but copied 1."""
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "src.bin"
            dest = Path(d) / "out.bin"
            payload = b"ABCDEFGH"
            src.write_bytes(payload)
            real_write = iso.os.write

            def one_byte(fd, data):
                if not data:
                    return 0
                return real_write(fd, data[:1])

            with mock.patch.object(iso.os, "write", side_effect=one_byte):
                n = iso._copy_regular_bounded(src, dest, 0, 64, chunk=8)
            self.assertEqual(n, len(payload))
            self.assertEqual(dest.read_bytes(), payload)

    def test_preexisting_prefix_map_is_never_removed(self):
        """Measured: pointer named _tree_prefix+'-victim' and materialize rmtree'd it.

        Prefix/key is not ownership. Product no longer deletes cross-run paths.
        """
        with tempfile.TemporaryDirectory() as hook:
            hook_path = Path(hook)
            old_td = tempfile.tempdir
            old_env = os.environ.get("TMPDIR")
            os.environ["TMPDIR"] = str(hook_path)
            tempfile.tempdir = None
            try:
                with tempfile.TemporaryDirectory() as d:
                    root = Path(d)
                    (root / "a.py").write_text("A\n", encoding="utf-8")
                    victim = hook_path / (iso._tree_prefix(root) + "-victim")
                    victim.mkdir()
                    marker = victim / "keep.txt"
                    marker.write_bytes(b"PREEXISTING_PREFIX_MAP\n")
                    tree = iso.IsolatedMutationTree(root)
                    try:
                        isolated = tree.materialize()
                        self.assertTrue(marker.is_file())
                        self.assertEqual(marker.read_bytes(), b"PREEXISTING_PREFIX_MAP\n")
                        self.assertNotEqual(isolated.resolve(), victim.resolve())
                    finally:
                        tree.cleanup()
                    self.assertTrue(marker.is_file())
                    self.assertEqual(marker.read_bytes(), b"PREEXISTING_PREFIX_MAP\n")
                    self.assertTrue(victim.is_dir())
            finally:
                if old_env is None:
                    os.environ.pop("TMPDIR", None)
                else:
                    os.environ["TMPDIR"] = old_env
                tempfile.tempdir = old_td

    def test_executable_mode_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            script = root / "tool.sh"
            script.write_text("#!/bin/sh\necho x\n", encoding="utf-8")
            os.chmod(script, 0o755)
            plain = root / "plain.txt"
            plain.write_text("noexec\n", encoding="utf-8")
            os.chmod(plain, 0o644)
            tree = iso.IsolatedMutationTree(root)
            try:
                isolated = tree.materialize()
                copied = isolated / "tool.sh"
                self.assertTrue(stat.S_IMODE(copied.stat().st_mode) & 0o111)
                self.assertFalse(stat.S_IMODE((isolated / "plain.txt").stat().st_mode) & 0o111)
            finally:
                tree.cleanup()

    def test_fifo_is_refused_and_original_untouched(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("os.mkfifo is unavailable")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "keep.py").write_text("ok\n", encoding="utf-8")
            os.mkfifo(root / "pipe")
            before = (root / "keep.py").read_bytes()
            tree = iso.IsolatedMutationTree(root)
            with self.assertRaises(iso.IsolationError) as cm:
                tree.materialize()
            msg = str(cm.exception).lower()
            self.assertTrue(any(w in msg for w in ("fifo", "socket", "device", "special")))
            self.assertEqual((root / "keep.py").read_bytes(), before)
            tree.cleanup()

    def test_context_manager_cleans_up_on_exception(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.py").write_text("A\n", encoding="utf-8")
            held = None
            with self.assertRaises(RuntimeError):
                with iso.IsolatedMutationTree(root) as isolated:
                    held = isolated
                    self.assertTrue((isolated / "a.py").is_file())
                    raise RuntimeError("forced")
            self.assertIsNotNone(held)
            self.assertFalse(Path(held).exists())

    def test_cleanup_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.py").write_text("A\n", encoding="utf-8")
            tree = iso.IsolatedMutationTree(root)
            isolated = tree.materialize()
            tree.cleanup()
            tree.cleanup()
            self.assertFalse(Path(isolated).exists())






    def test_user_dir_with_muttree_prefix_is_copied(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            kept = root / "corpus-adequacy-muttree-userdir"
            kept.mkdir()
            (kept / "payload.txt").write_text("KEEP_USERDIR\n", encoding="utf-8")
            (root / "a.py").write_text("A\n", encoding="utf-8")
            tree = iso.IsolatedMutationTree(root)
            try:
                isolated = tree.materialize()
                copied = isolated / "corpus-adequacy-muttree-userdir" / "payload.txt"
                self.assertTrue(copied.is_file())
                self.assertEqual(copied.read_text(encoding="utf-8"), "KEEP_USERDIR\n")
            finally:
                tree.cleanup()

    def test_oversize_copy_refuses_without_a_large_allocation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            payload = b"Z" * 80
            (root / "big.bin").write_bytes(payload)
            dest = Path(d) / "out.bin"
            with self.assertRaises(iso.IsolationError) as cm:
                iso._copy_regular_bounded(root / "big.bin", dest, 0, 40, chunk=16)
            self.assertIn("40", str(cm.exception))
            self.assertFalse(dest.exists())
            self.assertEqual((root / "big.bin").read_bytes(), payload)

    def test_growing_file_cannot_bypass_cap_in_memory(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "grow.bin"
            dest = Path(d) / "out.bin"
            src.write_bytes(b"a" * 8)
            real_read = iso.os.read
            state = {"n": 0}

            def read_then_grow(fd, n):
                data = real_read(fd, n)
                state["n"] += 1
                if state["n"] == 1:
                    with open(src, "ab") as fh:
                        fh.write(b"b" * 80)
                return data

            with mock.patch.object(iso.os, "read", side_effect=read_then_grow):
                with self.assertRaises(iso.IsolationError) as cm:
                    iso._copy_regular_bounded(src, dest, 0, 32, chunk=8)
            self.assertTrue("32" in str(cm.exception) or "ceiling" in str(cm.exception).lower())
            self.assertFalse(dest.exists())
            self.assertLessEqual(8, 32)


@unittest.skipIf(ca.fcntl is None, "process/batch lock is POSIX")
@unittest.skipIf(not hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW is required")
class TreeLockNoFollow(unittest.TestCase):
    def test_lock_open_does_not_follow_or_truncate_a_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            victim = Path(tempfile.mkstemp(prefix="iso-lock-victim-", dir=tempfile.gettempdir())[1])
            secret = b"LOCK_SYMLINK_PROBE_BYTES\n"
            victim.write_bytes(secret)
            lock = ca._TreeLock(root)
            if lock.path.exists() or lock.path.is_symlink():
                lock.path.unlink()
            lock.path.symlink_to(victim)
            try:
                with self.assertRaises(ca.ManifestError) as cm:
                    lock.__enter__()
                self.assertFalse(lock.held)
                self.assertEqual(victim.read_bytes(), secret)
                self.assertIn("regular file", str(cm.exception).lower())
            finally:
                if lock._fh is not None:
                    lock.__exit__()
                if lock.path.is_symlink():
                    lock.path.unlink()
                try:
                    victim.unlink()
                except OSError:
                    pass


@unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
class IsolatedRun(unittest.TestCase):
    def test_normal_success_scores_and_removes_the_home(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = _write_batch_corpus(tmp)
            before = (tmp / "check.py").read_bytes()
            rep = ca.run(manifest, execution_profile="trusted-local")
            self.assertEqual(rep["killed"], 1)
            self.assertTrue(rep["adequate"], rep["failures"])
            self.assertEqual((tmp / "check.py").read_bytes(), before)
            self.assertFalse(_prefix_dirs(Path(tempfile.gettempdir()), tmp))

    def test_dirty_declared_source_is_measured_not_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = _write_batch_corpus(tmp)
            _git(tmp, "init")
            _git(tmp, "add", "check.py")
            _git(tmp, "commit", "-m", "tracked")
            dirty = (tmp / "check.py").read_text(encoding="utf-8") + "# DIRTY_DECLARED\n"
            (tmp / "check.py").write_text(dirty, encoding="utf-8")
            (tmp / "notes.txt").write_text("UNTRACKED\n", encoding="utf-8")
            before_src = (tmp / "check.py").read_bytes()
            before_notes = (tmp / "notes.txt").read_bytes()
            rep = ca.run(manifest, execution_profile="trusted-local")
            self.assertEqual(rep["killed"], 1)
            self.assertTrue(rep["adequate"], rep["failures"])
            self.assertEqual((tmp / "check.py").read_bytes(), before_src)
            self.assertEqual((tmp / "notes.txt").read_bytes(), before_notes)
            self.assertFalse(_prefix_dirs(Path(tempfile.gettempdir()), tmp))
            self.assertIn(b"DIRTY_DECLARED", before_src)

    def test_symlink_escape_in_the_tree_refuses_run_and_leaves_outside(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = _write_batch_corpus(tmp)
            outside = tmp / "outside.txt"
            # repo_root is tmp; put the escape target outside tmp
            # Use a sibling of tmp... TemporaryDirectory is the repo.
            # Create a file in gettempdir() outside this repo.
            outside_dir = Path(tempfile.mkdtemp(prefix="iso-outside-"))
            try:
                secret = outside_dir / "secret.txt"
                secret.write_text("OUTSIDE_SECRET\n", encoding="utf-8")
                before = secret.read_bytes()
                (tmp / "escape").symlink_to(secret)
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.run(manifest, execution_profile="trusted-local")
                self.assertIn("symlink", str(cm.exception).lower())
                self.assertEqual(secret.read_bytes(), before)
                self.assertFalse(_prefix_dirs(Path(tempfile.gettempdir()), tmp))
            finally:
                secret = outside_dir / "secret.txt"
                if secret.exists():
                    secret.unlink()
                outside_dir.rmdir()

    def test_oversized_materialization_refuses_without_writing_original(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = _write_batch_corpus(tmp)
            (tmp / "pad.bin").write_bytes(b"Y" * 100)
            before = {
                path: path.read_bytes()
                for path in tmp.rglob("*") if path.is_file() and not path.is_symlink()
            }
            with mock.patch.object(iso, "MATERIALIZATION_CAP_BYTES", 20):
                with self.assertRaises(ca.ManifestError) as cm:
                    ca.run(manifest, execution_profile="trusted-local")
            self.assertTrue("20" in str(cm.exception) or "ceiling" in str(cm.exception).lower()
                            or "cap" in str(cm.exception).lower())
            now = {
                path: path.read_bytes()
                for path in tmp.rglob("*") if path.is_file() and not path.is_symlink()
            }
            self.assertEqual(now, before)
            self.assertFalse(_prefix_dirs(Path(tempfile.gettempdir()), tmp))

    def test_vanished_declared_source_refuses_without_writing_original(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = _write_batch_corpus(tmp)
            other = tmp / "vectors.json"
            other_before = other.read_bytes()
            loaded = ca.load_manifest(manifest)
            (tmp / "check.py").unlink()
            with self.assertRaises(ca.ManifestError):
                ca._run_process(loaded, manifest, execution_profile="trusted-local")
            self.assertEqual(other.read_bytes(), other_before)
            self.assertFalse((tmp / "check.py").exists())
            self.assertFalse(_prefix_dirs(Path(tempfile.gettempdir()), tmp))

    def test_exception_after_materialize_cleans_home_and_releases_lock(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = _write_batch_corpus(tmp)
            before = (tmp / "check.py").read_bytes()
            loaded = ca.load_manifest(manifest)
            with mock.patch.object(ca, "_build", side_effect=RuntimeError("forced")):
                with self.assertRaises(RuntimeError):
                    ca._run_process(loaded, manifest, execution_profile="trusted-local")
            self.assertEqual((tmp / "check.py").read_bytes(), before)
            self.assertFalse(_prefix_dirs(Path(tempfile.gettempdir()), tmp))
            _assert_lock_releasable(self, tmp)

    def test_run_capped_cwd_is_the_isolated_tree(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = _write_batch_corpus(tmp)
            before = (tmp / "check.py").read_bytes()
            captured = []
            real = ca._run_capped

            def capture(cmd, cwd, timeout):
                captured.append(Path(cwd).resolve())
                return real(cmd, cwd, timeout)

            with mock.patch.object(ca, "_run_capped", side_effect=capture):
                rep = ca.run(manifest, execution_profile="trusted-local")
            self.assertEqual(rep["killed"], 1)
            self.assertTrue(captured)
            sys_tmp = Path(tempfile.gettempdir()).resolve()
            first = captured[0]
            for cwd in captured:
                self.assertEqual(cwd, first)
                self.assertNotEqual(cwd, tmp.resolve())
                self.assertFalse(_under(cwd, tmp))
                self.assertTrue(_under(cwd, sys_tmp))
            self.assertEqual((tmp / "check.py").read_bytes(), before)
            self.assertFalse(first.exists())
            self.assertFalse(_prefix_dirs(Path(tempfile.gettempdir()), tmp))

            captured.clear()
            with mock.patch.object(ca, "_run_capped", side_effect=capture):
                ca.run(manifest, execution_profile="trusted-local")
            self.assertTrue(captured)
            self.assertNotEqual(captured[0], first)
            self.assertFalse(_under(captured[0], tmp))

    def test_successful_run_does_not_write_the_original(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = _write_batch_corpus(tmp)
            before = (tmp / "check.py").read_bytes()
            ca.run(manifest, execution_profile="trusted-local")
            self.assertEqual((tmp / "check.py").read_bytes(), before)
            self.assertNotIn(b"MUTANT_VISIBLE", before)


@unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
@unittest.skipIf(not hasattr(signal, "SIGKILL"), "SIGKILL is POSIX")
class ExternalProcessSigkill(unittest.TestCase):
    """Abrupt SIGKILL of the tool cannot run Python finally.

    Only the recorded tool-child (and descendants of that session) are
    signalled. The unmutated baseline completes quickly; the mutant is
    visible on disk in the isolated copy before that entrypoint starts.
    """

    def test_sigkill_leaves_the_declared_checkout_byte_identical(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as child_tmp:
            repo = Path(d)
            child_tmp_path = Path(child_tmp)
            manifest = _write_batch_corpus(repo, one_mutant=True, sleep_mutant=True)
            _git(repo, "init")
            _git(repo, "add", "check.py")
            _git(repo, "commit", "-m", "tracked source")
            dirty_src = (repo / "check.py").read_text(encoding="utf-8")
            dirty_src = "# DIRTY_DECLARED\n" + dirty_src
            (repo / "check.py").write_text(dirty_src, encoding="utf-8")
            (repo / "notes.txt").write_text("UNTRACKED_BYTES\n", encoding="utf-8")
            before_src = (repo / "check.py").read_bytes()
            before_notes = (repo / "notes.txt").read_bytes()
            first_root = None
            env = os.environ.copy()
            env["TMPDIR"] = str(child_tmp_path)
            env["TEMP"] = str(child_tmp_path)
            env["TMP"] = str(child_tmp_path)

            proc = subprocess.Popen(
                [sys.executable, str(Path(ca.__file__).resolve()), str(manifest)],
                cwd=str(repo),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            pid = proc.pid
            self.assertIsInstance(pid, int)
            self.assertGreater(pid, 0)
            deadline = time.monotonic() + 20
            seen = False
            try:
                while time.monotonic() < deadline:
                    for named in _prefix_dirs(child_tmp_path, repo):
                        first_root = named
                        isolated_src = named / "check.py"
                        if isolated_src.is_file():
                            try:
                                text = isolated_src.read_text(encoding="utf-8")
                            except OSError:
                                text = ""
                            if "MUTANT_VISIBLE" in text:
                                seen = True
                                break
                    if seen:
                        break
                    if proc.poll() is not None:
                        break
                    time.sleep(0.05)
                if not seen:
                    _reap_tool_group(pid)
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    self.fail("timed out waiting for isolated mutant bytes (pid=%s)" % pid)
                os.kill(pid, signal.SIGKILL)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    _reap_tool_group(pid)
                    proc.wait(timeout=5)
            finally:
                if proc.poll() is None:
                    _reap_tool_group(pid)
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                else:
                    _reap_tool_group(pid)

            self.assertEqual((repo / "check.py").read_bytes(), before_src)
            self.assertEqual((repo / "notes.txt").read_bytes(), before_notes)
            self.assertIsNotNone(first_root)
            # SIGKILL cannot run finally. The prefix orphan may remain.
            self.assertTrue(Path(first_root).is_dir())

            follow = _write_batch_corpus(repo, one_mutant=False, sleep_mutant=False)
            (repo / "check.py").write_bytes(before_src)
            (repo / "notes.txt").write_bytes(before_notes)
            captured = []
            real = ca._run_capped

            def capture(cmd, cwd, timeout):
                captured.append(Path(cwd).resolve())
                return real(cmd, cwd, timeout)

            with mock.patch.object(ca, "_run_capped", side_effect=capture):
                rep = ca.run(follow, execution_profile="trusted-local")
            self.assertIsNotNone(rep.get("score_percent"))
            self.assertEqual(rep["killed"], 1)
            self.assertEqual((repo / "check.py").read_bytes(), before_src)
            self.assertEqual((repo / "notes.txt").read_bytes(), before_notes)
            self.assertTrue(captured)
            self.assertNotEqual(captured[0], Path(first_root).resolve())
            self.assertFalse(_under(captured[0], repo))
            # Next run does not auto-delete the SIGKILL orphan.
            self.assertTrue(Path(first_root).is_dir())


if __name__ == "__main__":
    unittest.main(verbosity=2)
