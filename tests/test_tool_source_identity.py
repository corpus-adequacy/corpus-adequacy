#!/usr/bin/env python3
"""Tool-source identity contract: a report never attributes modified runtime
bytes to the clean HEAD commit. Standard library only.

One producer, `tool_identity(root)`, answers four fields for one ordered
explicit set of runtime sources, `TOOL_SOURCE_PATHS`:

- `tool_commit`   40-hex HEAD, or None. Never a SHA carrying a dirty marker.
- `tool_source_state`  exact | dirty | unresolved.
- `tool_content_sha256`  sha256 over an ordered, length-delimited stream of
  (relative path bytes, raw file bytes), or None when those bytes do not exist.
- `tool_version`  unchanged.

The state ladder is a distinction between two different failures:

- `unresolved` means the comparison could not be established at all — no git,
  an unresolvable HEAD, or a `git show` that failed;
- `dirty` means the comparison was established and the worktree differs, which
  includes a declared path that is no longer a regular in-root file.

`exact` names the bytes on disk. It is deliberately not index-aware: what a
staged blob contains is not what the interpreter executes, so a worktree
restored to HEAD bytes is exact even while `git status` calls it modified.
That is also why porcelain is not the source of truth here.

Non-claims. This proves which declared tool bytes differ from HEAD. It is not
an attestation, not a signature, not an SBOM, not a claim that the recorded
bytes are the code objects already loaded in `sys.modules`, and not a claim
that the checkout or its environment is reproducible.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
import corpus_adequacy as ca  # noqa: E402

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_FIELD_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

EXPECTED_TOOL_SOURCE_PATHS = (
    "bounded_run.py",
    "corpus_adequacy.py",
    "isolated_tree.py",
    "module_child.py",
)


def _git_env() -> dict:
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "Fixture"
    env["GIT_AUTHOR_EMAIL"] = "fixture@example.com"
    env["GIT_COMMITTER_NAME"] = "Fixture"
    env["GIT_COMMITTER_EMAIL"] = "fixture@example.com"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    """Fixture git. autocrlf is pinned off so a fixture means one thing."""
    cmd = [
        "git",
        "-c", "user.name=Fixture",
        "-c", "user.email=fixture@example.com",
        "-c", "commit.gpgsign=false",
        "-c", "core.autocrlf=false",
        "-c", "core.eol=lf",
        "-C", str(root),
        *args,
    ]
    return subprocess.run(cmd, check=True, capture_output=True, env=_git_env())


def _write_runtime_tree(root: Path) -> None:
    for name in EXPECTED_TOOL_SOURCE_PATHS:
        (root / name).write_bytes(b"# %s\nMARK = 0\n" % name.encode("utf-8"))
    (root / "README.md").write_text("# fixture\n", encoding="utf-8")
    (root / "tests").mkdir(exist_ok=True)
    (root / "tests" / "test_fixture.py").write_text("# fixture test\n", encoding="utf-8")


@contextmanager
def _repo(commit: bool = True):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        _write_runtime_tree(root)
        if commit:
            _git(root, "-c", "init.defaultBranch=main", "init", "-q")
            _git(root, "add", "-A")
            _git(root, "commit", "-qm", "fixture")
        yield root


def _head(root: Path) -> str:
    return _git(root, "rev-parse", "HEAD").stdout.decode("utf-8").strip()


def _reference_digest(root: Path, names=EXPECTED_TOOL_SOURCE_PATHS) -> str:
    """The documented stream, recomputed here so the format itself is pinned."""
    h = hashlib.sha256()
    h.update(ca.TOOL_SOURCE_DIGEST_TAG)
    for name in names:
        raw = name.encode("utf-8")
        data = (root / name).read_bytes()
        h.update(b"%d\n" % len(raw))
        h.update(raw)
        h.update(b"%d\n" % len(data))
        h.update(data)
    return "sha256:" + h.hexdigest()


class DeclaredRuntimeSurface(unittest.TestCase):
    """The set is explicit, ordered, and pinned against the shipped tree."""

    def test_tool_source_paths_is_the_ordered_post_11_runtime_set(self):
        self.assertEqual(ca.TOOL_SOURCE_PATHS, EXPECTED_TOOL_SOURCE_PATHS)

    def test_every_runtime_module_in_the_repository_root_is_declared(self):
        shipped = tuple(sorted(p.name for p in REPO_ROOT.glob("*.py")))
        self.assertEqual(tuple(sorted(ca.TOOL_SOURCE_PATHS)), shipped)

    def test_dropping_a_declared_path_changes_the_content_digest(self):
        with _repo() as root:
            full = ca.tool_identity(root)["tool_content_sha256"]
            self.assertEqual(full, _reference_digest(root))
            for dropped in EXPECTED_TOOL_SOURCE_PATHS:
                short = tuple(n for n in EXPECTED_TOOL_SOURCE_PATHS if n != dropped)
                with self.subTest(dropped=dropped):
                    self.assertNotEqual(full, _reference_digest(root, short))


class CleanCheckoutIsExact(unittest.TestCase):
    def test_clean_tracked_checkout_names_head(self):
        with _repo() as root:
            identity = ca.tool_identity(root)
            expected_head = _head(root)
        self.assertEqual(identity["tool_source_state"], "exact")
        self.assertEqual(identity["tool_commit"], expected_head)
        self.assertRegex(identity["tool_commit"], HEX40_RE)
        self.assertRegex(identity["tool_content_sha256"], SHA256_FIELD_RE)
        self.assertEqual(identity["tool_version"], ca.VERSION)

    def test_digest_is_the_documented_length_delimited_stream(self):
        with _repo() as root:
            self.assertEqual(
                ca.tool_identity(root)["tool_content_sha256"],
                _reference_digest(root),
            )

    def test_digest_is_stable_across_calls_and_independent_of_cwd(self):
        with _repo() as root:
            first = ca.tool_identity(root)["tool_content_sha256"]
            cwd = os.getcwd()
            os.chdir(tempfile.gettempdir())
            try:
                second = ca.tool_identity(root)["tool_content_sha256"]
            finally:
                os.chdir(cwd)
        self.assertEqual(first, second)

    def test_unrelated_readme_and_test_dirt_stays_exact(self):
        with _repo() as root:
            clean = ca.tool_identity(root)
            (root / "README.md").write_text("# edited after the commit\n", encoding="utf-8")
            (root / "tests" / "test_fixture.py").write_text("# edited\n", encoding="utf-8")
            (root / "untracked.txt").write_text("stray\n", encoding="utf-8")
            dirty_docs = ca.tool_identity(root)
        self.assertEqual(dirty_docs["tool_source_state"], "exact")
        self.assertEqual(dirty_docs["tool_commit"], clean["tool_commit"])
        self.assertEqual(dirty_docs["tool_content_sha256"], clean["tool_content_sha256"])

    def test_pycache_and_stray_pyc_do_not_affect_identity(self):
        with _repo() as root:
            clean = ca.tool_identity(root)
            cache = root / "__pycache__"
            cache.mkdir()
            (cache / "corpus_adequacy.cpython-313.pyc").write_bytes(b"\x00compiled")
            (root / "module_child.pyc").write_bytes(b"\x00compiled")
            after = ca.tool_identity(root)
        self.assertEqual(after["tool_source_state"], "exact")
        self.assertEqual(after["tool_commit"], clean["tool_commit"])
        self.assertEqual(after["tool_content_sha256"], clean["tool_content_sha256"])


class ModifiedRuntimeSourceIsNeverExact(unittest.TestCase):
    """Each declared member, one at a time. Hashing only the controller bites."""

    def test_each_runtime_member_unstaged_edit_is_dirty(self):
        for name in EXPECTED_TOOL_SOURCE_PATHS:
            with self.subTest(name):
                with _repo() as root:
                    clean = ca.tool_identity(root)
                    with (root / name).open("ab") as fh:
                        fh.write(b"# uncommitted line\n")
                    identity = ca.tool_identity(root)
                self.assertEqual(identity["tool_source_state"], "dirty")
                self.assertIsNone(identity["tool_commit"])
                self.assertRegex(identity["tool_content_sha256"], SHA256_FIELD_RE)
                self.assertNotEqual(
                    identity["tool_content_sha256"], clean["tool_content_sha256"]
                )

    def test_each_runtime_member_staged_edit_is_dirty(self):
        for name in EXPECTED_TOOL_SOURCE_PATHS:
            with self.subTest(name):
                with _repo() as root:
                    with (root / name).open("ab") as fh:
                        fh.write(b"# staged line\n")
                    _git(root, "add", name)
                    identity = ca.tool_identity(root)
                self.assertEqual(identity["tool_source_state"], "dirty")
                self.assertIsNone(identity["tool_commit"])

    def test_worktree_matching_the_index_but_not_head_is_dirty(self):
        with _repo() as root:
            with (root / "isolated_tree.py").open("ab") as fh:
                fh.write(b"# staged and left in place\n")
            _git(root, "add", "isolated_tree.py")
            identity = ca.tool_identity(root)
        self.assertEqual(identity["tool_source_state"], "dirty")
        self.assertIsNone(identity["tool_commit"])

    def test_index_only_change_with_worktree_back_at_head_is_exact(self):
        """The index is not what the interpreter executes; porcelain would lie
        the other way here, which is why porcelain is not the source of truth."""
        with _repo() as root:
            head_bytes = (root / "bounded_run.py").read_bytes()
            (root / "bounded_run.py").write_bytes(head_bytes + b"# staged only\n")
            _git(root, "add", "bounded_run.py")
            (root / "bounded_run.py").write_bytes(head_bytes)
            identity = ca.tool_identity(root)
            porcelain = _git(root, "status", "--porcelain").stdout.decode("utf-8")
            expected_head = _head(root)
            expected_digest = _reference_digest(root)
        self.assertIn("bounded_run.py", porcelain)
        self.assertEqual(identity["tool_source_state"], "exact")
        self.assertEqual(identity["tool_commit"], expected_head)
        self.assertEqual(identity["tool_content_sha256"], expected_digest)

    def test_a_dirty_report_never_carries_the_head_sha_anywhere(self):
        with _repo() as root:
            head = _head(root)
            with (root / "corpus_adequacy.py").open("ab") as fh:
                fh.write(b"# uncommitted line\n")
            identity = ca.tool_identity(root)
            rendered = ca.format_tool_identity(identity)
        self.assertNotIn(head, json.dumps(identity))
        self.assertNotIn(head, rendered)
        self.assertNotIn("-dirty", rendered)

    def test_commit_is_a_bare_40_hex_commit_or_null_in_every_state(self):
        cases = []
        with _repo() as root:
            cases.append(ca.tool_identity(root))
            with (root / "module_child.py").open("ab") as fh:
                fh.write(b"# uncommitted line\n")
            cases.append(ca.tool_identity(root))
        with _repo(commit=False) as root:
            cases.append(ca.tool_identity(root))
        for identity in cases:
            with self.subTest(identity["tool_source_state"]):
                commit = identity["tool_commit"]
                if identity["tool_source_state"] == "exact":
                    self.assertRegex(commit, HEX40_RE)
                else:
                    self.assertIsNone(commit)


class UnresolvableIdentityIsNotExact(unittest.TestCase):
    def test_checkout_without_git_is_unresolved_but_keeps_the_digest(self):
        with _repo(commit=False) as root:
            identity = ca.tool_identity(root)
            expected_digest = _reference_digest(root)
        self.assertEqual(identity["tool_source_state"], "unresolved")
        self.assertIsNone(identity["tool_commit"])
        self.assertEqual(identity["tool_content_sha256"], expected_digest)
        self.assertEqual(identity["tool_version"], ca.VERSION)

    def _fail_git(self, first_arg: str, returncode: int = 128):
        real = ca._git_bytes

        def wrapper(root, *args):
            if args and args[0] == first_arg:
                return subprocess.CompletedProcess(
                    args=list(args), returncode=returncode, stdout=b"", stderr=b"boom"
                )
            return real(root, *args)

        return mock.patch.object(ca, "_git_bytes", wrapper)

    def test_failed_rev_parse_is_unresolved(self):
        with _repo() as root:
            with self._fail_git("rev-parse"):
                identity = ca.tool_identity(root)
        self.assertEqual(identity["tool_source_state"], "unresolved")
        self.assertIsNone(identity["tool_commit"])
        self.assertRegex(identity["tool_content_sha256"], SHA256_FIELD_RE)

    def test_failed_git_show_is_unresolved(self):
        with _repo() as root:
            with self._fail_git("show"):
                identity = ca.tool_identity(root)
        self.assertEqual(identity["tool_source_state"], "unresolved")
        self.assertIsNone(identity["tool_commit"])

    def test_non_hex_rev_parse_output_is_unresolved(self):
        real = ca._git_bytes

        def wrapper(root, *args):
            if args and args[0] == "rev-parse":
                return subprocess.CompletedProcess(
                    args=list(args), returncode=0, stdout=b"HEAD\n", stderr=b""
                )
            return real(root, *args)

        with _repo() as root:
            with mock.patch.object(ca, "_git_bytes", wrapper):
                identity = ca.tool_identity(root)
        self.assertEqual(identity["tool_source_state"], "unresolved")
        self.assertIsNone(identity["tool_commit"])

    def test_git_binary_absent_is_unresolved_not_a_traceback(self):
        with _repo() as root:
            with mock.patch.object(ca.subprocess, "run", side_effect=OSError("no git")):
                identity = ca.tool_identity(root)
        self.assertEqual(identity["tool_source_state"], "unresolved")
        self.assertIsNone(identity["tool_commit"])

    def test_shallow_clone_resolves_its_own_head(self):
        with _repo() as root, tempfile.TemporaryDirectory() as dest:
            clone = Path(dest).resolve() / "shallow"
            subprocess.run(
                ["git", "clone", "-q", "--depth", "1", root.as_uri(), str(clone)],
                check=True, capture_output=True, env=_git_env(),
            )
            self.assertTrue((clone / ".git" / "shallow").exists())
            identity = ca.tool_identity(clone)
            expected_head = _head(clone)
        self.assertEqual(identity["tool_source_state"], "exact")
        self.assertEqual(identity["tool_commit"], expected_head)


class RuntimePathIsARegularInRootFile(unittest.TestCase):
    def test_a_deleted_runtime_member_is_never_exact(self):
        with _repo() as root:
            (root / "module_child.py").unlink()
            identity = ca.tool_identity(root)
        self.assertEqual(identity["tool_source_state"], "dirty")
        self.assertIsNone(identity["tool_commit"])
        self.assertIsNone(identity["tool_content_sha256"])

    def _require_symlinks(self, root: Path) -> None:
        try:
            (root / "_probe").symlink_to(root / "README.md")
        except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
            self.skipTest("symlinks unavailable here: %s" % exc)
        (root / "_probe").unlink()

    def test_a_symlinked_runtime_member_with_identical_bytes_is_never_exact(self):
        with _repo() as root:
            self._require_symlinks(root)
            target = root / "copy_of_child.py"
            member = root / "module_child.py"
            target.write_bytes(member.read_bytes())
            member.unlink()
            member.symlink_to(target)
            self.assertEqual(member.read_bytes(), target.read_bytes())
            identity = ca.tool_identity(root)
        self.assertEqual(identity["tool_source_state"], "dirty")
        self.assertIsNone(identity["tool_commit"])
        self.assertIsNone(identity["tool_content_sha256"])

    def test_an_out_of_root_runtime_member_is_never_exact(self):
        with _repo() as root:
            self._require_symlinks(root)
            outside = root.parent / "outside_child.py"
            member = root / "module_child.py"
            outside.write_bytes(member.read_bytes())
            member.unlink()
            member.symlink_to(outside)
            identity = ca.tool_identity(root)
            outside.unlink()
        self.assertEqual(identity["tool_source_state"], "dirty")
        self.assertIsNone(identity["tool_commit"])

    def test_a_directory_in_place_of_a_runtime_member_is_never_exact(self):
        with _repo() as root:
            member = root / "isolated_tree.py"
            member.unlink()
            member.mkdir()
            identity = ca.tool_identity(root)
        self.assertEqual(identity["tool_source_state"], "dirty")
        self.assertIsNone(identity["tool_commit"])


class OneProducerFeedsEveryRenderer(unittest.TestCase):
    def test_formatter_renders_the_given_identity_without_recomputing(self):
        identity = {
            "tool_version": "9.9.9",
            "tool_commit": None,
            "tool_source_state": "dirty",
            "tool_content_sha256": "sha256:" + "ab" * 32,
        }
        with mock.patch.object(
            ca, "tool_identity", side_effect=AssertionError("formatter recomputed")
        ):
            line = ca.format_tool_identity(identity)
        self.assertIn("corpus-adequacy 9.9.9", line)
        self.assertIn("dirty", line)
        self.assertIn("sha256:" + "ab" * 32, line)

    def test_formatter_tolerates_a_report_without_the_additive_fields(self):
        line = ca.format_tool_identity({"tool_version": "0.1.0", "tool_commit": None})
        self.assertIn("corpus-adequacy 0.1.0", line)

    def test_report_identity_is_produced_once_per_report(self):
        calls = []
        real = ca.tool_identity

        def counting(root=None):
            calls.append(root)
            return real(root)

        with mock.patch.object(ca, "tool_identity", counting):
            report = ca._with_tool_identity({"schema": "corpus-adequacy.report.v0"})
        self.assertEqual(len(calls), 1)
        for field in (
            "tool_version", "tool_commit", "tool_source_state", "tool_content_sha256",
        ):
            self.assertIn(field, report)

    def test_version_flag_prints_state_and_content_digest(self):
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "corpus_adequacy.py"), "--version"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0)
        line = result.stdout.strip()
        self.assertEqual(line, ca.format_tool_identity())
        self.assertIn("corpus-adequacy %s" % ca.VERSION, line)
        self.assertRegex(line, r"source=(exact|dirty|unresolved)")
        self.assertRegex(line, r"content=(sha256:[0-9a-f]{64}|none)")

    def test_text_report_renders_the_reports_own_identity(self):
        report = {
            "schema": "corpus-adequacy.report.v0", "manifest": "m.json",
            "killed": 1, "survived": 0, "equivalent": 0, "known_holes": 0,
            "unexercised_out_of_scope": 0, "unproved": 0, "declared_total": 1,
            "out_of_scope_ratio": 0.0, "hole_ratio": 0.0, "score_percent": 100.0,
            "score_means": "author-declared", "adequate": True, "failures": [],
            "tool_version": "0.1.0", "tool_commit": None,
            "tool_source_state": "dirty",
            "tool_content_sha256": "sha256:" + "cd" * 32,
            "mutants": [{"group": "g", "verdict": "killed",
                         "label": "threshold", "how": "unexpected-exit"}],
        }
        import io
        buf = io.StringIO()
        with mock.patch.object(ca, "run", return_value=report), \
                mock.patch.object(
                    ca, "tool_identity",
                    side_effect=AssertionError("text report recomputed identity")), \
                mock.patch.object(sys, "argv", ["corpus_adequacy.py", "m.json"]), \
                mock.patch("sys.stdout", buf):
            rc = ca.main()
        self.assertEqual(rc, 0)
        self.assertIn("dirty", buf.getvalue())
        self.assertIn("sha256:" + "cd" * 32, buf.getvalue())

    def test_this_checkout_is_internally_consistent(self):
        identity = ca.tool_identity()
        self.assertIn(
            identity["tool_source_state"], ("exact", "dirty", "unresolved")
        )
        if identity["tool_source_state"] == "exact":
            self.assertRegex(identity["tool_commit"], HEX40_RE)
        else:
            self.assertIsNone(identity["tool_commit"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
