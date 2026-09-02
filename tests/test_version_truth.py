#!/usr/bin/env python3
"""Version/release-truth contract. Standard library only.

One function. VERSION is read via ast.parse of corpus_adequacy.py — no import,
no exec, no runpy. A missing local tag is honest. This is not a release,
not a tag, not protection, and does not make 0.1.0 addressable.

The 0.1.0 heading was introduced with VERSION itself at
7491548357d65e45cf3db5a40a05ad0375c6d02b, dated 2026-08-19 when the version
was named, not cut. RELEASE_DATES independently pins the actual cut date.
"""

from __future__ import annotations

import ast
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
SEMVER_RE = re.compile(r"^" + SEMVER + r"$")
UNRELEASED_HEADING_RE = re.compile(r"^##\s+\[?Unreleased\]?\s*$")
TAG_SCHEMA_PHRASE = "The git tag is `v` plus that same number."
CUT_ORDER_PHRASE = "The cut order is cut → dated heading → VERSION → tag."
NO_ADDRESSABILITY_PHRASE = (
    "Quoting a version is not a tag and does not make the tag addressable."
)
RELEASE_TRUTH_BLOCK = "%s %s %s" % (
    TAG_SCHEMA_PHRASE,
    CUT_ORDER_PHRASE,
    NO_ADDRESSABILITY_PHRASE,
)
RELEASE_DATES = {
    "0.1.0": "2026-08-22",
    "0.1.1": "2026-08-22",
    "0.1.2": "2026-08-23",
    "0.1.3": "2026-09-02",
}


def check_version_release_truth(root: Path) -> str:
    """One rule: version/release truth for a checkout.

    1. ast.parse corpus_adequacy.py. One collector lists conservative
       runtime-rebinding forms (Name Store/Del, def/class name,
       arguments, except-as, import/from-import, match name/rest).
       It does not cover PEP 695 type parameters or other syntactic
       bindings. from-import * is unknown and refused. Exactly one
       VERSION binding, and it is the direct top-level simple Assign.
       This does not exec the module or prove globals()/exec reflection.
    2. CHANGELOG has exactly one Unreleased heading and exactly one dated
       heading for that VERSION. The real ISO calendar date must equal the
       independently pinned RELEASE_DATES entry.
    3. Public README must contain RELEASE_TRUTH_BLOCK as one full
       trimmed line. The literal v<VERSION> is forbidden only while
       that tag is demonstrably absent.
    4. No git metadata: treat as no tag. In a checkout, show-ref --verify
       --quiet maps rc 1 to absent and any other nonzero to error. A
       present ref must be an annotated tag object, then is read via git show
       tag:path, run through the same public-markdown + heading/docs checks,
       and must have an empty public Unreleased body (fenced leftover notes
       still fail).

    Returns the parsed VERSION. Raises ValueError on any violation.
    """
    root = Path(root)
    version = _parse_version_text((root / "corpus_adequacy.py").read_text(encoding="utf-8"))
    changelog = _public_markdown((root / "CHANGELOG.md").read_text(encoding="utf-8"))
    readme = _public_markdown((root / "README.md").read_text(encoding="utf-8"))
    _check_changelog_headings(changelog, version)
    tag_present = _tag_is_present(root, version)
    _check_docs_wording(readme, changelog, version, tag_present)
    if tag_present:
        _check_tagged_tree(root, version)
    return version


class _BindingCollector(ast.NodeVisitor):
    """Conservative runtime-rebinding names. Not PEP 695. No exec."""

    def __init__(self):
        self.names: list[str] = []
        self.star_import = False

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.append(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.append(node.name)
        self._bind_arguments(node.args)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.append(node.name)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names.append(node.name)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self.names.append(alias.asname)
            else:
                self.names.append(alias.name.split(".")[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                self.star_import = True
                continue
            self.names.append(alias.asname or alias.name)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.names.append(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.names.append(node.name)
        self.generic_visit(node)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.names.append(node.rest)
        self.generic_visit(node)

    def _bind_arguments(self, args: ast.arguments) -> None:
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            self.names.append(arg.arg)
        if args.vararg:
            self.names.append(args.vararg.arg)
        if args.kwarg:
            self.names.append(args.kwarg.arg)


def _parse_version_text(source: str) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ValueError("corpus_adequacy.py is not parseable: %s" % exc) from exc
    collector = _BindingCollector()
    collector.visit(tree)
    if collector.star_import:
        raise ValueError("from-import * leaves VERSION unknown")
    if collector.names.count("VERSION") != 1:
        raise ValueError(
            "need exactly one VERSION binding, found %d"
            % collector.names.count("VERSION")
        )
    assignment = None
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == "VERSION":
            assignment = node
            break
    if assignment is None:
        raise ValueError(
            "the VERSION binding is not a direct top-level simple Assign"
        )
    value = assignment.value
    if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
        raise ValueError(
            "VERSION must be a quoted MAJOR.MINOR.PATCH string literal"
        )
    if SEMVER_RE.match(value.value) is None:
        raise ValueError("VERSION is not strict semver: %r" % value.value)
    return value.value


_FENCE_LINE_RE = re.compile(r"^( {0,3})(`{3,}|~{3,})(.*)$")


def _strip_html_comments(text: str) -> str:
    pieces = []
    cursor = 0
    while True:
        start = text.find("<!--", cursor)
        if start < 0:
            pieces.append(text[cursor:])
            return "".join(pieces)
        pieces.append(text[cursor:start])
        end = text.find("-->", start + 4)
        if end < 0:
            return "".join(pieces)
        cursor = end + 3


def _indented_code_line(line: str) -> bool:
    raw = line[:-1] if line.endswith("\n") else line
    if raw.endswith("\r"):
        raw = raw[:-1]
    return raw.startswith("\t") or raw.startswith("    ")


def _fence_line(line: str):
    match = _FENCE_LINE_RE.match(line.rstrip("\n"))
    if match is None:
        return None
    run = match.group(2)
    return run[0], len(run), match.group(3)


def _public_markdown(text: str) -> str:
    """Outward Markdown only: drop HTML comments and fenced code.

    Supported boundary, not a full parser:
    - HTML comments: <!-- ... --> including across lines. An unclosed
      <!-- consumes the rest of the file.
    - Fenced blocks: opener is 0-3 spaces then 3+ ` or ~. A closer is
      0-3 spaces, the same character, at least as long as the opener,
      and trailing whitespace only. An unclosed fence consumes the rest.
    - Indented code: a line that starts with a tab or 4+ spaces is
      dropped. Conservative CommonMark; nested lists/quote-indents
      that use 4 spaces are also dropped. Inline `code` stays.
    Other HTML is left as-is.
    """
    lines = _strip_html_comments(text).splitlines(keepends=True)
    out = []
    fence = None
    for line in lines:
        parsed = _fence_line(line)
        if fence is None:
            if parsed is not None:
                fence = (parsed[0], parsed[1])
                continue
            if _indented_code_line(line):
                continue
            out.append(line)
            continue
        if (
            parsed is not None
            and parsed[0] == fence[0]
            and parsed[1] >= fence[1]
            and parsed[2].strip() == ""
        ):
            fence = None
    return "".join(out)


ATX_HEADING_RE = re.compile(r"^( {0,3})(##(?!#)[ 	]+.+)$")


def _atx_heading(line: str) -> str | None:
    """CommonMark level-2 ATX heading: 0-3 leading spaces, then ##.

    Returns the heading without the leading spaces, or None.
    Level 1 and 3-6 headings are not a section boundary.
    """
    match = ATX_HEADING_RE.match(line)
    if match is None:
        return None
    return match.group(2)


def _headings(text: str) -> list[str]:
    found = []
    for line in text.splitlines():
        heading = _atx_heading(line)
        if heading is not None:
            found.append(heading)
    return found


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
        dated.append((heading, match.group(1)))
    version_headings = [h for h in headings if version_heading_re.match(h)]
    dated_headings = {heading for heading, _ in dated}
    undated = [h for h in version_headings if h not in dated_headings]
    if undated:
        raise ValueError(
            "CHANGELOG heading for %s is missing an ISO date: %r" % (version, undated)
        )
    if len(dated) != 1:
        raise ValueError(
            "CHANGELOG must have exactly one dated heading for %s, found %d"
            % (version, len(dated))
        )
    expected = RELEASE_DATES.get(version)
    if expected is None:
        raise ValueError("no release date is pinned for %s" % version)
    if dated[0][1] != expected:
        raise ValueError(
            "CHANGELOG date for %s is %s, expected %s"
            % (version, dated[0][1], expected)
        )


def _check_docs_wording(
    readme: str, changelog: str, version: str, tag_present: bool
) -> None:
    if not any(line.strip() == RELEASE_TRUTH_BLOCK for line in readme.splitlines()):
        raise ValueError(
            "README must contain the exact release-truth block as one line"
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
        encoding="utf-8",
        errors="strict",
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
    object_type = _git(root, "cat-file", "-t", ref)
    if object_type.returncode != 0:
        raise ValueError(
            "git cat-file -t failed for %s (rc=%d)"
            % (ref, object_type.returncode)
        )
    if object_type.stdout.strip() != "tag":
        raise ValueError(
            "%s is a %s object, not an annotated tag"
            % (ref, object_type.stdout.strip() or "missing")
        )
    return True


def _unreleased_body(changelog: str) -> str:
    lines = changelog.splitlines()
    start = None
    for i, line in enumerate(lines):
        heading = _atx_heading(line)
        if heading is not None and UNRELEASED_HEADING_RE.match(heading):
            start = i + 1
            break
    if start is None:
        raise ValueError("tagged CHANGELOG has no Unreleased heading")
    body = []
    for line in lines[start:]:
        if _atx_heading(line) is not None:
            break
        body.append(line)
    return "\n".join(body).strip()


def _show_tagged_file(root: Path, tag: str, path: str) -> str:
    shown = _git(root, "show", "%s:%s" % (tag, path))
    if shown.returncode != 0:
        raise ValueError("tag %s exists but has no %s" % (tag, path))
    return shown.stdout


def _check_tagged_tree(root: Path, version: str) -> None:
    tag = "v" + version
    tagged_version = _parse_version_text(
        _show_tagged_file(root, tag, "corpus_adequacy.py")
    )
    if tagged_version != version:
        raise ValueError(
            "tag %s has VERSION %s, not %s" % (tag, tagged_version, version)
        )
    raw_changelog = _show_tagged_file(root, tag, "CHANGELOG.md")
    raw_readme = _show_tagged_file(root, tag, "README.md")
    changelog = _public_markdown(raw_changelog)
    readme = _public_markdown(raw_readme)
    _check_changelog_headings(changelog, version)
    _check_docs_wording(readme, changelog, version, True)
    if _unreleased_body(changelog):
        raise ValueError("tag %s has a non-empty public Unreleased section" % tag)
    if _unreleased_body(raw_changelog):
        raise ValueError(
            "tag %s hides Unreleased notes in a fence or comment" % tag
        )


def _honest_readme(extra: str = "") -> str:
    if extra:
        return RELEASE_TRUTH_BLOCK + "\n" + extra.lstrip() + "\n"
    return RELEASE_TRUTH_BLOCK + "\n"


def _honest_changelog(version: str = "0.1.0") -> str:
    return (
        "# Changelog\n\n"
        "## Unreleased\n\n"
        "## %s — %s\n\n"
        "First named cut of the extracted tool.\n"
        % (version, RELEASE_DATES.get(version, RELEASE_DATES["0.1.0"]))
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
    _git_fixture(root, "tag", "-a", name, "-m", name)


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
    ("docstring-only", '"""\nVERSION = "0.1.0"\n"""\n'),
    ("nested-function", 'def _f():\n    VERSION = "0.1.0"\n'),
    ("nested-class", "class C:\n    VERSION = \"0.1.0\"\n"),
    ("attribute-assignment", "mod = type('m', (), {})()\nmod.VERSION = \"0.1.0\"\n"),
    ("two-module-level", 'VERSION = "0.1.0"\nVERSION = "0.2.0"\n'),
    ("ann-assign", 'VERSION: str = "0.1.0"\n'),
    ("augassign", 'VERSION = "0.1.0"\nVERSION += "1"\n'),
    (
        "if-rebind",
        'VERSION = "0.1.0"\nif True:\n    VERSION = "0.2.0"\n',
    ),
    (
        "function-global",
        'VERSION = "0.1.0"\ndef _f():\n    global VERSION\n'
        '    VERSION = "0.2.0"\n_f()\n',
    ),
    ("import-alias", 'from x import foo as VERSION\nVERSION = "0.1.0"\n'),
    ("def-VERSION", 'VERSION = "0.1.0"\ndef VERSION():\n    pass\n'),
    ("class-VERSION", 'VERSION = "0.1.0"\nclass VERSION:\n    pass\n'),
    ("star-import", 'VERSION = "0.1.0"\nfrom x import *\n'),
    (
        "except-as-VERSION",
        'VERSION = "0.1.0"\ntry:\n    pass\n'
        "except Exception as VERSION:\n    pass\n",
    ),
    ("import-VERSION-sub", 'import VERSION.sub\nVERSION = "0.1.0"\n'),
)

INVALID_CHANGELOGS = (
    (
        "unreleased-removed",
        "# Changelog\n\n## 0.1.0 — 2026-08-22\n\nFirst named cut.\n",
    ),
    (
        "unreleased-doubled",
        "# Changelog\n\n## Unreleased\n\n## Unreleased\n\n"
        "## 0.1.0 — 2026-08-22\n\nFirst named cut.\n",
    ),
    ("dated-removed", "# Changelog\n\n## Unreleased\n\nlater work.\n"),
    (
        "dated-doubled",
        "# Changelog\n\n## Unreleased\n\n"
        "## 0.1.0 — 2026-08-22\n\nFirst named cut.\n\n"
        "## 0.1.0 — 2026-08-23\n\nDuplicate.\n",
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
    (
        "headings-only-in-fence",
        "# Changelog\n\n```\n## Unreleased\n\n"
        "## 0.1.0 — 2026-08-22\n```\n",
    ),
    (
        "headings-only-in-comment",
        "# Changelog\n\n<!--\n## Unreleased\n\n"
        "## 0.1.0 — 2026-08-22\n-->\n",
    ),
    (
        "headings-after-unclosed-comment",
        "# Changelog\n\n<!--\n## Unreleased\n\n"
        "## 0.1.0 — 2026-08-22\n",
    ),
    (
        "unreleased-indented-duplicate",
        "# Changelog\n\n## Unreleased\n\n ## Unreleased\n\n"
        "## 0.1.0 — 2026-08-22\n\nFirst named cut.\n",
    ),
    (
        "dated-indented-duplicate",
        "# Changelog\n\n## Unreleased\n\n"
        "## 0.1.0 — 2026-08-22\n\nFirst named cut.\n\n"
        " ## 0.1.0 — 2026-08-23\n\nDuplicate.\n",
    ),
)


class VersionReleaseTruth(unittest.TestCase):
    def test_checkout_satisfies_version_release_truth(self):
        self.assertEqual(check_version_release_truth(REPO_ROOT), "0.1.3")

    def test_v013_changelog_names_the_trusted_local_boundary(self):
        changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        section = changelog.split("## 0.1.3 — 2026-09-02", 1)[1].split(
            "## 0.1.2", 1
        )[0]
        self.assertIn("trusted-local", section)
        self.assertIn("trusted inputs", section)
        self.assertIn("not a sandbox", section)

    def test_release_date_is_pinned_independently(self):
        with _temp_tree(
            changelog=_honest_changelog().replace(
                RELEASE_DATES["0.1.0"], "2026-08-23"
            )
        ) as root:
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_lightweight_tag_is_not_a_release_tag(self):
        with _temp_tree() as root:
            _init_git_repo(root)
            _git_fixture(root, "tag", "v0.1.0")
            with self.assertRaises(ValueError):
                check_version_release_truth(root)

    def test_module_docstring_names_the_root_invocation(self):
        source = (REPO_ROOT / "corpus_adequacy.py").read_text(encoding="utf-8")
        doc = ast.get_docstring(ast.parse(source))
        self.assertIsNotNone(doc)
        self.assertIn("python3 corpus_adequacy.py", doc)
        self.assertNotIn("conformance/corpus_adequacy.py", doc)

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
            ("phrases-only-in-fence", "```\n" + _honest_readme() + "```\n"),
            ("phrases-only-in-comment", "<!--\n" + _honest_readme() + "-->\n"),
            ("phrases-after-unclosed-comment", "<!--\n" + _honest_readme()),
            (
                "fence-closer-with-trailing-text",
                "```\n``` not a closer\n" + _honest_readme() + "```\n",
            ),
            (
                "four-space-line-is-not-a-closer",
                "```\n    ```\n" + _honest_readme() + "```\n",
            ),
            (
                "phrases-only-indented-spaces",
                "".join(
                    ("    " + line if line.strip() else line)
                    for line in _honest_readme().splitlines(True)
                ),
            ),
            (
                "phrases-only-indented-tab",
                "".join(
                    ("\t" + line if line.strip() else line)
                    for line in _honest_readme().splitlines(True)
                ),
            ),
            (
                "phrases-only-in-reference-titles",
                (
                    '[schema]: https://example.test "%s"\n'
                    '[order]: https://example.test "%s"\n'
                    '[addr]: https://example.test "%s"\n'
                    % (
                        TAG_SCHEMA_PHRASE,
                        CUT_ORDER_PHRASE,
                        NO_ADDRESSABILITY_PHRASE,
                    )
                ),
            ),
            (
                "block-only-in-one-reference-title",
                '[truth]: https://example.test "%s"\n' % RELEASE_TRUTH_BLOCK,
            ),
        )
        for name, readme in cases:
            with self.subTest(name):
                with _temp_tree(readme=readme) as root:
                    with self.assertRaises(ValueError):
                        check_version_release_truth(root)

    def test_phrases_after_a_real_fence_closer_are_public(self):
        with _temp_tree(readme="```\nhidden\n```\n" + _honest_readme()) as root:
            self.assertEqual(check_version_release_truth(root), "0.1.0")

    def _tag_bad_tree_then_heal(self, root):
        _init_git_repo(root)
        _tag(root, "v0.1.0")
        _write_tree(root)
        _git_fixture(root, "add", "-A")
        _git_fixture(root, "commit", "-m", "heal")

    def test_tagged_tree_must_match_public_docs(self):
        cases = (
            (
                "tag-without-dated-heading",
                {"changelog": "# Changelog\n\n## Unreleased\n\n"},
            ),
            (
                "tag-unreleased-hidden-in-fence",
                {
                    "changelog": (
                        "# Changelog\n\n## Unreleased\n\n"
                        "```\nLater work.\n```\n\n"
                        "## 0.1.0 — 2026-08-22\n\nFirst named cut.\n"
                    )
                },
            ),
            (
                "tag-without-readme-release-text",
                {"readme": "no release procedure here\n"},
            ),
            (
                "tag-unreleased-h3-added-is-still-body",
                {
                    "changelog": (
                        "# Changelog\n\n## Unreleased\n\n"
                        "### Added\n\nLater work.\n\n"
                        "## 0.1.0 — 2026-08-22\n\nFirst named cut.\n"
                    )
                },
            ),
        )
        for name, kwargs in cases:
            with self.subTest(name):
                with _temp_tree(**kwargs) as root:
                    self._tag_bad_tree_then_heal(root)
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
                "## 0.1.0 — 2026-08-22\n\nFirst named cut.\n",
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

    def test_git_decodes_tagged_unicode_as_utf8_strict(self):
        self.assertIn("\u2014", _honest_changelog())
        self.assertIn("\u2192", RELEASE_TRUTH_BLOCK)
        recorded = []
        real_run = subprocess.run

        def wrapper(*args, **kwargs):
            if kwargs.get("text"):
                recorded.append(dict(kwargs))
            return real_run(*args, **kwargs)

        with _temp_tree() as root:
            _init_git_repo(root)
            _tag(root, "v0.1.0")
            with patch.object(subprocess, "run", wrapper):
                self.assertEqual(check_version_release_truth(root), "0.1.0")
        self.assertTrue(recorded)
        for kwargs in recorded:
            self.assertEqual(kwargs.get("encoding"), "utf-8")
            self.assertEqual(kwargs.get("errors"), "strict")


if __name__ == "__main__":
    unittest.main(verbosity=1)
