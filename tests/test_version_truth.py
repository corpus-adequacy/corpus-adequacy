#!/usr/bin/env python3
"""Version/release-truth contract. Standard library only.

One function. VERSION is read as text from corpus_adequacy.py — no import,
no exec, no runpy. A missing local tag is honest. This is not a release,
not a tag, not protection, and does not make 0.1.0 addressable.

The dated 0.1.0 heading already in CHANGELOG (em dash, 2026-08-19) was
introduced with VERSION itself at 7491548357d65e45cf3db5a40a05ad0375c6d02b.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SEMVER = r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
# Module-level assignment only. Quoted string, optional trailing comment.
VERSION_ASSIGN_RE = re.compile(
    r"^VERSION\s*=\s*(['\"])(" + SEMVER + r")\1\s*(?:#.*)?$"
)
VERSION_LINE_RE = re.compile(r"^VERSION\s*=")
UNRELEASED_HEADING_RE = re.compile(r"^##\s+\[?Unreleased\]?\s*$")
TAG_SCHEMA_PHRASE = "The git tag is `v` plus that same number."
CUT_ORDER_PHRASE = "cut → dated heading → VERSION → tag"


def check_version_release_truth(root: Path) -> str:
    """One rule: version/release truth for a checkout.

    1. Parse VERSION from corpus_adequacy.py as text (quoted x.y.z only).
    2. CHANGELOG has exactly one Unreleased heading and exactly one dated
       heading for that VERSION (ISO date in the heading).
    3. Docs name the tag schema (`v` + VERSION) and the cut order; they
       must not name `v<VERSION>` as if that tag were addressable.
    4. If local tag v<VERSION> is missing: honest, pass. If it exists:
       that commit's tree must carry the same VERSION string and an empty
       Unreleased section.

    Returns the parsed VERSION. Raises ValueError on any violation.
    """
    root = Path(root)
    version = _parse_version_text((root / "corpus_adequacy.py").read_text(encoding="utf-8"))
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    _check_changelog_headings(changelog, version)
    _check_docs_wording(readme, changelog, version)
    _check_local_tag(root, version)
    return version


def _parse_version_text(source: str) -> str:
    assignments = []
    for line in source.splitlines():
        if VERSION_LINE_RE.match(line):
            assignments.append(line)
    if len(assignments) != 1:
        raise ValueError(
            "need exactly one module-level VERSION assignment, found %d"
            % len(assignments)
        )
    match = VERSION_ASSIGN_RE.match(assignments[0])
    if match is None:
        raise ValueError(
            "VERSION must be a quoted MAJOR.MINOR.PATCH string literal, got %r"
            % assignments[0]
        )
    return match.group(2)


def _headings(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("## ")]


def _check_changelog_headings(changelog: str, version: str) -> None:
    headings = _headings(changelog)
    unreleased = [h for h in headings if UNRELEASED_HEADING_RE.match(h)]
    if len(unreleased) != 1:
        raise ValueError(
            "CHANGELOG must have exactly one Unreleased heading, found %d"
            % len(unreleased)
        )
    dated_re = re.compile(
        r"^##\s+\[?" + re.escape(version) + r"\]?\s+[—–-]\s+(\d{4}-\d{2}-\d{2})\s*$"
    )
    version_heading_re = re.compile(
        r"^##\s+\[?" + re.escape(version) + r"\]?(\s|$)"
    )
    dated = [h for h in headings if dated_re.match(h)]
    version_headings = [h for h in headings if version_heading_re.match(h)]
    undated = [h for h in version_headings if h not in dated]
    if undated:
        raise ValueError(
            "CHANGELOG heading for %s is missing an ISO date: %r" % (version, undated)
        )
    if len(dated) != 1:
        raise ValueError(
            "CHANGELOG must have exactly one dated heading for %s, found %d"
            % (version, len(dated))
        )


def _folded(text: str) -> str:
    return " ".join(text.split())


def _check_docs_wording(readme: str, changelog: str, version: str) -> None:
    folded = _folded(readme)
    if TAG_SCHEMA_PHRASE not in folded:
        raise ValueError("README must state the tag schema: %r" % TAG_SCHEMA_PHRASE)
    if CUT_ORDER_PHRASE not in folded:
        raise ValueError(
            "README must state the cut order: %r" % CUT_ORDER_PHRASE
        )
    tag_name = "v" + version
    # Docs may describe the schema (`v` plus VERSION) but must not name the
    # current tag as if it existed. CHANGELOG headings use 0.1.0, not v0.1.0.
    for label, body in (("README", readme), ("CHANGELOG", changelog)):
        if tag_name in body:
            raise ValueError(
                "%s must not name %s as if that tag were addressable" % (label, tag_name)
            )


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        env=env,
    )


def _unreleased_body(changelog: str) -> str:
    lines = changelog.splitlines()
    start = None
    for i, line in enumerate(lines):
        if UNRELEASED_HEADING_RE.match(line):
            start = i + 1
            break
    if start is None:
        raise ValueError("tagged CHANGELOG has no Unreleased heading")
    body = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        body.append(line)
    return "\n".join(body).strip()


def _check_local_tag(root: Path, version: str) -> None:
    inside = _git(root, "rev-parse", "--is-inside-work-tree")
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return
    tag = "v" + version
    found = _git(root, "rev-parse", "-q", "--verify", "refs/tags/" + tag)
    if found.returncode != 0:
        return  # missing tag is honest
    shown = _git(root, "show", "%s:corpus_adequacy.py" % tag)
    if shown.returncode != 0:
        raise ValueError("tag %s exists but has no corpus_adequacy.py" % tag)
    tagged_version = _parse_version_text(shown.stdout)
    if tagged_version != version:
        raise ValueError(
            "tag %s has VERSION %s, not %s" % (tag, tagged_version, version)
        )
    log_shown = _git(root, "show", "%s:CHANGELOG.md" % tag)
    if log_shown.returncode != 0:
        raise ValueError("tag %s exists but has no CHANGELOG.md" % tag)
    if _unreleased_body(log_shown.stdout):
        raise ValueError("tag %s has a non-empty Unreleased section" % tag)


def _honest_readme() -> str:
    return (
        "%s The tag is applied only after the cut order: %s.\n"
        % (TAG_SCHEMA_PHRASE, CUT_ORDER_PHRASE)
    )


def _honest_changelog(version: str = "0.1.0") -> str:
    return (
        "# Changelog\n\n"
        "## Unreleased\n\n"
        "## %s — 2026-08-19\n\n"
        "First named cut of the extracted tool.\n" % version
    )


def _honest_source(version: str = "0.1.0") -> str:
    return 'VERSION = "%s"\n' % version


def _write_tree(root: Path, source=None, changelog=None, readme=None) -> None:
    (root / "corpus_adequacy.py").write_text(
        source if source is not None else _honest_source(), encoding="utf-8"
    )
    (root / "CHANGELOG.md").write_text(
        changelog if changelog is not None else _honest_changelog(), encoding="utf-8"
    )
    (root / "README.md").write_text(
        readme if readme is not None else _honest_readme(), encoding="utf-8"
    )


def _git_identity_env() -> dict:
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "Fixture"
    env["GIT_AUTHOR_EMAIL"] = "fixture@example.com"
    env["GIT_COMMITTER_NAME"] = "Fixture"
    env["GIT_COMMITTER_EMAIL"] = "fixture@example.com"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _init_git_repo(root: Path) -> None:
    env = _git_identity_env()
    subprocess.run(
        ["git", "-c", "init.defaultBranch=main", "init"],
        cwd=root,
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(
        ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", "add", "-A"],
        cwd=root,
        check=True,
        capture_output=True,
        env=env,
    )
    subprocess.run(
        [
            "git",
            "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.com",
            "-c", "commit.gpgsign=false",
            "commit",
            "-m", "fixture",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        env=env,
    )


def _tag(root: Path, name: str) -> None:
    env = _git_identity_env()
    subprocess.run(
        ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", "tag", name],
        cwd=root,
        check=True,
        capture_output=True,
        env=env,
    )


class VersionReleaseTruth(unittest.TestCase):
    def test_checkout_satisfies_version_release_truth(self):
        version = check_version_release_truth(REPO_ROOT)
        self.assertEqual(version, "0.1.0")

    def test_version_is_read_as_text_without_import_or_exec(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(
                root,
                source=(
                    "raise RuntimeError('imported or executed')\n"
                    'VERSION = "0.1.0"\n'
                ),
            )
            self.assertEqual(check_version_release_truth(root), "0.1.0")

    def test_non_semver_two_part_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(root, source='VERSION = "1.0"\n')
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_unquoted_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(root, source="VERSION = 0.1.0\n")
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_bool_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(root, source="VERSION = True\n")
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_prefixed_v_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(root, source='VERSION = "v0.1.0"\n')
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_leading_zeros_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(root, source='VERSION = "01.0.0"\n')
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_neighboring_true_is_not_accepted_as_version(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(
                root,
                source='FLAG = True\nVERSION = "0.1.0"\nNONE = None\nFALSE = False\n',
            )
            self.assertEqual(check_version_release_truth(root), "0.1.0")

    def test_unreleased_removed_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(
                root,
                changelog=(
                    "# Changelog\n\n"
                    "## 0.1.0 — 2026-08-19\n\n"
                    "First named cut.\n"
                ),
            )
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_unreleased_doubled_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(
                root,
                changelog=(
                    "# Changelog\n\n"
                    "## Unreleased\n\n"
                    "## Unreleased\n\n"
                    "## 0.1.0 — 2026-08-19\n\n"
                    "First named cut.\n"
                ),
            )
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_dated_heading_removed_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(
                root,
                changelog="# Changelog\n\n## Unreleased\n\nlater work.\n",
            )
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_dated_heading_doubled_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(
                root,
                changelog=(
                    "# Changelog\n\n"
                    "## Unreleased\n\n"
                    "## 0.1.0 — 2026-08-19\n\n"
                    "First named cut.\n\n"
                    "## 0.1.0 — 2026-08-20\n\n"
                    "Duplicate.\n"
                ),
            )
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_dated_heading_without_date_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(
                root,
                changelog=(
                    "# Changelog\n\n"
                    "## Unreleased\n\n"
                    "## 0.1.0\n\n"
                    "First named cut.\n"
                ),
            )
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_missing_tag_is_honest(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(root)
            _init_git_repo(root)
            listed = _git(root, "tag", "-l", "v0.1.0")
            self.assertEqual(listed.stdout.strip(), "")
            self.assertEqual(check_version_release_truth(root), "0.1.0")

    def test_matching_tag_with_empty_unreleased_passes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(root)
            _init_git_repo(root)
            _tag(root, "v0.1.0")
            self.assertEqual(check_version_release_truth(root), "0.1.0")

    def test_mismatched_tag_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            env = _git_identity_env()
            _write_tree(root, source='VERSION = "0.0.1"\n',
                        changelog=_honest_changelog("0.0.1"))
            _init_git_repo(root)
            _tag(root, "v0.1.0")
            (root / "corpus_adequacy.py").write_text(_honest_source("0.1.0"), encoding="utf-8")
            (root / "CHANGELOG.md").write_text(_honest_changelog("0.1.0"), encoding="utf-8")
            subprocess.run(
                ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", "add", "-A"],
                cwd=root, check=True, capture_output=True, env=env,
            )
            subprocess.run(
                [
                    "git", "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.com",
                    "-c", "commit.gpgsign=false",
                    "commit", "-m", "bump",
                ],
                cwd=root, check=True, capture_output=True, env=env,
            )
            # Working tree is 0.1.0; tag v0.1.0 points at 0.0.1.
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_tag_with_nonempty_unreleased_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(
                root,
                changelog=(
                    "# Changelog\n\n"
                    "## Unreleased\n\n"
                    "Later work still sitting under Unreleased.\n\n"
                    "## 0.1.0 — 2026-08-19\n\n"
                    "First named cut.\n"
                ),
            )
            _init_git_repo(root)
            _tag(root, "v0.1.0")
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_release_procedure_order_removed_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write_tree(root, readme=TAG_SCHEMA_PHRASE + "\n")
            with self.assertRaises(ValueError):
                check_version_release_truth(root)


if __name__ == "__main__":
    unittest.main(verbosity=1)
