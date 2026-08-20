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
from contextlib import contextmanager
from datetime import date
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent

SEMVER = r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
VERSION_ASSIGN_RE = re.compile(
    r"^VERSION\s*=\s*(['\"])(" + SEMVER + r")\1\s*(?:#.*)?$"
)
VERSION_LINE_RE = re.compile(r"^VERSION\s*=")
UNRELEASED_HEADING_RE = re.compile(r"^##\s+\[?Unreleased\]?\s*$")
TAG_SCHEMA_PHRASE = "The git tag is `v` plus that same number."
CUT_ORDER_PHRASE = "cut → dated heading → VERSION → tag"
NO_ADDRESSABILITY_PHRASE = (
    "Quoting a version is not a tag and does not make the tag addressable."
)


def check_version_release_truth(root: Path) -> str:
    """One rule: version/release truth for a checkout.

    1. Parse VERSION from corpus_adequacy.py as text (quoted x.y.z only).
    2. CHANGELOG has exactly one Unreleased heading and exactly one dated
       heading for that VERSION (real ISO calendar date).
    3. Docs name the tag schema, the cut order, and the no-addressability
       sentence. The literal v<VERSION> is forbidden only while that tag
       is demonstrably absent.
    4. No git metadata: treat as no tag. In a checkout, show-ref --verify
       --quiet maps rc 1 to absent and any other nonzero to error. A
       present tag's tree must carry the same VERSION and an empty
       Unreleased section.

    Returns the parsed VERSION. Raises ValueError on any violation.
    """
    root = Path(root)
    version = _parse_version_text((root / "corpus_adequacy.py").read_text(encoding="utf-8"))
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    _check_changelog_headings(changelog, version)
    tag_present = _tag_is_present(root, version)
    _check_docs_wording(readme, changelog, version, tag_present)
    if tag_present:
        _check_tagged_tree(root, version)
    return version


def _parse_version_text(source: str) -> str:
    assignments = [line for line in source.splitlines() if VERSION_LINE_RE.match(line)]
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
    dated = []
    for heading in headings:
        match = dated_re.match(heading)
        if match is None:
            continue
        try:
            date.fromisoformat(match.group(1))
        except ValueError as exc:
            raise ValueError(
                "CHANGELOG date is not a real calendar date: %r" % match.group(1)
            ) from exc
        dated.append(heading)
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


def _check_docs_wording(
    readme: str, changelog: str, version: str, tag_present: bool
) -> None:
    folded = _folded(readme)
    if TAG_SCHEMA_PHRASE not in folded:
        raise ValueError("README must state the tag schema: %r" % TAG_SCHEMA_PHRASE)
    if CUT_ORDER_PHRASE not in folded:
        raise ValueError("README must state the cut order: %r" % CUT_ORDER_PHRASE)
    if NO_ADDRESSABILITY_PHRASE not in folded:
        raise ValueError(
            "README must state that quoting a version is not addressable: %r"
            % NO_ADDRESSABILITY_PHRASE
        )
    if tag_present:
        return
    tag_name = "v" + version
    for label, body in (("README", readme), ("CHANGELOG", changelog)):
        if tag_name in body:
            raise ValueError(
                "%s must not name %s while that tag is absent" % (label, tag_name)
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


def _tag_is_present(root: Path, version: str) -> bool:
    if not (root / ".git").exists():
        return False
    ref = "refs/tags/v" + version
    try:
        result = _git(root, "show-ref", "--verify", "--quiet", ref)
    except OSError as exc:
        raise ValueError("git failed in a checkout: %s" % exc) from exc
    if result.returncode == 1:
        return False
    if result.returncode != 0:
        raise ValueError(
            "git show-ref --verify failed for %s (rc=%d)" % (ref, result.returncode)
        )
    return True


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


def _check_tagged_tree(root: Path, version: str) -> None:
    tag = "v" + version
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


def _honest_readme(extra: str = "") -> str:
    return (
        "%s The tag is applied only after the cut order: %s. %s%s\n"
        % (TAG_SCHEMA_PHRASE, CUT_ORDER_PHRASE, NO_ADDRESSABILITY_PHRASE, extra)
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


@contextmanager
def _temp_tree(**kwargs):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_tree(root, **kwargs)
        yield root


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


def _git_fixture(root: Path, *args: str) -> None:
    env = _git_identity_env()
    cmd = [
        "git",
        "-c", "user.name=Fixture",
        "-c", "user.email=fixture@example.com",
        "-c", "commit.gpgsign=false",
        *args,
    ]
    subprocess.run(cmd, cwd=root, check=True, capture_output=True, env=env)


def _init_git_repo(root: Path) -> None:
    env = _git_identity_env()
    subprocess.run(
        ["git", "-c", "init.defaultBranch=main", "init"],
        cwd=root,
        check=True,
        capture_output=True,
        env=env,
    )
    _git_fixture(root, "add", "-A")
    _git_fixture(root, "commit", "-m", "fixture")


def _tag(root: Path, name: str) -> None:
    _git_fixture(root, "tag", name)


def _show_ref_result(rc: int) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["git", "show-ref", "--verify", "--quiet"],
        returncode=rc,
        stdout="",
        stderr="",
    )


def _patch_show_ref(rc: int):
    real = _git

    def wrapper(root, *args):
        if args[:3] == ("show-ref", "--verify", "--quiet"):
            return _show_ref_result(rc)
        return real(root, *args)

    return patch(__name__ + "._git", wrapper)


INVALID_SOURCES = (
    ("two-part", 'VERSION = "1.0"\n'),
    ("unquoted", "VERSION = 0.1.0\n"),
    ("bool", "VERSION = True\n"),
    ("prefixed-v", 'VERSION = "v0.1.0"\n'),
    ("leading-zeros", 'VERSION = "01.0.0"\n'),
)

INVALID_CHANGELOGS = (
    (
        "unreleased-removed",
        "# Changelog\n\n## 0.1.0 — 2026-08-19\n\nFirst named cut.\n",
    ),
    (
        "unreleased-doubled",
        "# Changelog\n\n## Unreleased\n\n## Unreleased\n\n"
        "## 0.1.0 — 2026-08-19\n\nFirst named cut.\n",
    ),
    ("dated-removed", "# Changelog\n\n## Unreleased\n\nlater work.\n"),
    (
        "dated-doubled",
        "# Changelog\n\n## Unreleased\n\n"
        "## 0.1.0 — 2026-08-19\n\nFirst named cut.\n\n"
        "## 0.1.0 — 2026-08-20\n\nDuplicate.\n",
    ),
    (
        "dated-without-date",
        "# Changelog\n\n## Unreleased\n\n## 0.1.0\n\nFirst named cut.\n",
    ),
    (
        "impossible-calendar-date",
        "# Changelog\n\n## Unreleased\n\n"
        "## 0.1.0 — 2026-02-31\n\nFirst named cut.\n",
    ),
)


class VersionReleaseTruth(unittest.TestCase):
    def test_checkout_satisfies_version_release_truth(self):
        self.assertEqual(check_version_release_truth(REPO_ROOT), "0.1.0")

    def test_version_is_read_as_text_without_import_or_exec(self):
        with _temp_tree(
            source="raise RuntimeError('imported or executed')\nVERSION = \"0.1.0\"\n"
        ) as root:
            self.assertEqual(check_version_release_truth(root), "0.1.0")

    def test_neighboring_true_is_not_accepted_as_version(self):
        with _temp_tree(
            source='FLAG = True\nVERSION = "0.1.0"\nNONE = None\nFALSE = False\n'
        ) as root:
            self.assertEqual(check_version_release_truth(root), "0.1.0")

    def test_invalid_version_sources_are_rejected(self):
        for name, source in INVALID_SOURCES:
            with self.subTest(name):
                with _temp_tree(source=source) as root:
                    with self.assertRaises(ValueError):
                        check_version_release_truth(root)

    def test_invalid_changelogs_are_rejected(self):
        for name, changelog in INVALID_CHANGELOGS:
            with self.subTest(name):
                with _temp_tree(changelog=changelog) as root:
                    with self.assertRaises(ValueError):
                        check_version_release_truth(root)

    def test_docs_must_keep_schema_order_and_no_addressability(self):
        cases = (
            ("cut-order-removed", TAG_SCHEMA_PHRASE + " " + NO_ADDRESSABILITY_PHRASE + "\n"),
            ("schema-removed", CUT_ORDER_PHRASE + " " + NO_ADDRESSABILITY_PHRASE + "\n"),
            ("no-addressability-removed", TAG_SCHEMA_PHRASE + " " + CUT_ORDER_PHRASE + "\n"),
            ("explicit-tag-while-absent", _honest_readme(" See v0.1.0.")),
        )
        for name, readme in cases:
            with self.subTest(name):
                with _temp_tree(readme=readme) as root:
                    with self.assertRaises(ValueError):
                        check_version_release_truth(root)

    def test_explicit_tag_token_is_allowed_once_the_tag_exists(self):
        with _temp_tree(readme=_honest_readme(" See v0.1.0.")) as root:
            _init_git_repo(root)
            _tag(root, "v0.1.0")
            self.assertEqual(check_version_release_truth(root), "0.1.0")

    def test_git_tag_fixtures(self):
        cases = (
            ("missing-tag-honest", False, None, False),
            ("matching-empty-unreleased", True, None, False),
            (
                "nonempty-unreleased",
                True,
                "# Changelog\n\n## Unreleased\n\nLater work.\n\n"
                "## 0.1.0 — 2026-08-19\n\nFirst named cut.\n",
                True,
            ),
        )
        for name, tag, changelog, must_fail in cases:
            with self.subTest(name):
                kwargs = {} if changelog is None else {"changelog": changelog}
                with _temp_tree(**kwargs) as root:
                    _init_git_repo(root)
                    if tag:
                        _tag(root, "v0.1.0")
                    if must_fail:
                        with self.assertRaises(ValueError):
                            check_version_release_truth(root)
                    else:
                        self.assertEqual(check_version_release_truth(root), "0.1.0")

    def test_mismatched_tag_is_rejected(self):
        with _temp_tree(
            source='VERSION = "0.0.1"\n', changelog=_honest_changelog("0.0.1")
        ) as root:
            _init_git_repo(root)
            _tag(root, "v0.1.0")
            (root / "corpus_adequacy.py").write_text(_honest_source("0.1.0"), encoding="utf-8")
            (root / "CHANGELOG.md").write_text(_honest_changelog("0.1.0"), encoding="utf-8")
            _git_fixture(root, "add", "-A")
            _git_fixture(root, "commit", "-m", "bump")
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_show_ref_rc1_is_absent_and_honest(self):
        with _temp_tree() as root:
            _init_git_repo(root)
            _tag(root, "v0.1.0")
            with _patch_show_ref(1):
                self.assertEqual(check_version_release_truth(root), "0.1.0")

    def test_show_ref_rc128_in_a_checkout_is_hard_error(self):
        with _temp_tree() as root:
            _init_git_repo(root)
            with _patch_show_ref(128):
                with self.assertRaises(ValueError):
                    check_version_release_truth(root)


if __name__ == "__main__":
    unittest.main(verbosity=1)
