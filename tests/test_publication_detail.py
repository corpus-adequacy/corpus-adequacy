#!/usr/bin/env python3
"""RED-first publication details: one loader, deterministic deep links, no JS."""

from __future__ import annotations

import html
import hashlib
import json
import os
import signal
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import corpus_adequacy as ca  # noqa: E402
import render_publication_page as rpp  # noqa: E402
from test_publication_page import VALID, _write_index, _write_tree  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "publication"
SURVIVED_SILENT = FIXTURES / "survived-silent"
BUILD = "a" * 40
REC = "survived-silent"
RUN = "runs/%s/index.html" % REC
SURVIVED = "runs/%s/rules/0000.html" % REC
SILENT = "runs/%s/rules/0001.html" % REC


class _Blocked(BaseException):
    """Not an OSError, so a blocked open cannot be converted into a refusal."""


def _site(root: Path, source_commit: str = BUILD) -> dict[str, bytes]:
    return rpp.render_site(root, source_commit)


def _text(files: dict[str, bytes], rel: str) -> str:
    return files[rel].decode("utf-8")


def _manifest_tree(tmpdir: Path, manifest: dict, *, report_fixture=SURVIVED_SILENT) -> tuple[Path, Path]:
    root = _write_tree(tmpdir, [report_fixture / "report.v0.json"], dummy_manifest=False)
    directory = report_fixture.name
    measurement = root / "measurements" / directory
    manifest_path = measurement / "manifest.json"
    raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    manifest_path.write_bytes(raw)
    report_path = measurement / "report.v0.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["manifest_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_index(root)
    return root, manifest_path


def _manifest_v0(*, anchor="if True:\n    do_check()") -> dict:
    return {
        "schema": ca.SCHEMA,
        "mutants": {
            "axis-a": [
                {"label": "survived-rule", "anchor": anchor},
                {"label": "killed-rule", "anchor": "killed_anchor"},
            ],
            "axis-b": [{"label": "silent-rule", "anchor": "silent_anchor"}],
        },
    }


def _manifest_v1(*, rule_text="The checker rejects the bad input.", anchor="if True:\n    do_check()") -> dict:
    doc = _manifest_v0(anchor=anchor)
    doc["schema"] = ca.MANIFEST_V1_SCHEMA
    doc["rules"] = {
        "axis-a": [
            {
                "id": "RULE-01",
                "text": rule_text,
                "url": "https://example.test/spec#rule-01",
                "disposition": "mutated",
                "mutants": ["survived-rule"],
            },
            {
                "id": "RULE-03",
                "text": "The checker retains the accepted outcome.",
                "url": "https://example.test/spec#rule-03",
                "disposition": "mutated",
                "mutants": ["killed-rule"],
            },
        ],
        "axis-b": [
            {
                "id": "RULE-02",
                "text": "The checker preserves the diagnostic reason.",
                "url": "https://example.test/spec#rule-02",
                "disposition": "mutated",
                "mutants": ["silent-rule"],
            }
        ],
    }
    return doc


class RuleLinkedDossier(unittest.TestCase):
    @staticmethod
    def _projection(root: Path) -> tuple[str, dict]:
        index_bytes, records = rpp.load_listed_records(root)
        renderer = rpp.read_bounded_regular_file(Path(rpp.__file__))
        return (
            rpp.compute_projection_digest(index_bytes, records, renderer, BUILD),
            records[0],
        )

    def test_v1_rule_and_exact_bound_anchor_share_one_page(self):
        with tempfile.TemporaryDirectory() as d:
            root, _manifest = _manifest_tree(Path(d), _manifest_v1())
            page = _text(_site(root), SURVIVED)
            self.assertIn("RULE-01", page)
            self.assertIn("The checker rejects the bad input.", page)
            self.assertIn("https://example.test/spec#rule-01", page)
            self.assertIn("if True:    do_check()", page)
            self.assertIn("verdict mechanism declared outcome unchanged", page)
            self.assertIn("diagnostic_channel_declared <span class=\"mono\">true</span>", page)
            self.assertIn("runner <span class=\"mono\">process</span>", page)

    def test_v0_anchor_is_bound_but_rule_inventory_is_unavailable(self):
        with tempfile.TemporaryDirectory() as d:
            root, _manifest = _manifest_tree(Path(d), _manifest_v0())
            page = _text(_site(root), SURVIVED)
            self.assertIn("if True:    do_check()", page)
            self.assertIn("unavailable (manifest.v0)", page)
            self.assertNotIn("RULE-01", page)

    def test_digest_mismatch_neither_crashes_nor_ingests_poison(self):
        with tempfile.TemporaryDirectory() as d:
            root, manifest = _manifest_tree(Path(d), _manifest_v1())
            poison = _manifest_v1(rule_text="POISON_RULE_TEXT", anchor="POISON_ANCHOR")
            poison["rules"]["axis-a"][0]["id"] = "POISON_RULE_ID"
            manifest.write_text(json.dumps(poison), encoding="utf-8")
            page = _text(_site(root), SURVIVED)
            for token in ("POISON_RULE_TEXT", "POISON_RULE_ID", "POISON_ANCHOR"):
                self.assertNotIn(token, page)
            self.assertIn("unavailable (manifest digest mismatch)", page)
            self.assertIn("omitted (manifest digest mismatch)", page)
            self.assertIn(">survived<", page)

    def test_missing_manifest_keeps_report_facts_and_names_absence(self):
        with tempfile.TemporaryDirectory() as d:
            root, manifest = _manifest_tree(Path(d), _manifest_v1())
            manifest.unlink()
            page = _text(_site(root), SURVIVED)
            self.assertIn("unavailable (manifest absent)", page)
            self.assertIn("omitted (manifest absent)", page)
            self.assertIn(">survived<", page)

    def test_matching_malformed_manifest_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            root, manifest = _manifest_tree(Path(d), _manifest_v1())
            raw = b"{"
            manifest.write_bytes(raw)
            report_path = manifest.parent / "report.v0.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["manifest_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            _write_index(root)
            with self.assertRaises(rpp.PublicationError):
                _site(root)

    def test_rule_and_anchor_derive_from_one_bounded_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            root, manifest = _manifest_tree(Path(d), _manifest_v1())
            real = rpp.read_bounded_regular_file
            reads = []

            def once(path, *args, **kwargs):
                if Path(path) == manifest:
                    reads.append(Path(path))
                    if len(reads) > 1:
                        return json.dumps(_manifest_v1(
                            rule_text="POISON_SECOND_READ", anchor="POISON_SECOND_ANCHOR"
                        )).encode("utf-8")
                return real(path, *args, **kwargs)

            with mock.patch.object(rpp, "read_bounded_regular_file", once):
                page = _text(_site(root), SURVIVED)
            self.assertEqual(reads, [manifest])
            self.assertIn("RULE-01", page)
            self.assertIn("if True:    do_check()", page)
            self.assertNotIn("POISON_SECOND", page)

    def test_hostile_rule_and_anchor_text_is_escaped(self):
        hostile = '\"><img src=x onerror=alert(1)><script>alert(1)</script>'
        with tempfile.TemporaryDirectory() as d:
            root, _manifest = _manifest_tree(
                Path(d), _manifest_v1(rule_text=hostile, anchor=hostile)
            )
            page = _text(_site(root), SURVIVED)
            self.assertNotIn("<script>", page)
            self.assertNotIn('<img src=x onerror=', page)
            self.assertIn("&lt;script&gt;", page)
            self.assertIn("&quot;&gt;&lt;img", page)

    def test_oversized_anchor_is_explicitly_omitted(self):
        with tempfile.TemporaryDirectory() as d:
            root, _manifest = _manifest_tree(
                Path(d), _manifest_v1(anchor="x" * (ca.ANCHOR_EXCERPT_MAX + 1))
            )
            page = _text(_site(root), SURVIVED)
            self.assertIn("omitted (oversized)", page)
            self.assertNotIn("x" * ca.ANCHOR_EXCERPT_MAX, page)

    def test_invalid_control_and_null_score_are_visibly_unscored(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [FIXTURES / "unproved-control" / "report.v0.json"])
            files = _site(root)
            page = _text(files, "runs/unproved-control/rules/0000.html")
            self.assertIn("control_status <span>survived</span>", page)
            self.assertIn("control invalid: run is unscored", page)
            self.assertIn("unproved <span class=\"mono\">3</span>", page)
            self.assertNotIn("runs/unproved-control/rules/0001.html", files)

    def test_projection_digest_binds_accepted_snapshot_and_unavailable_state(self):
        with tempfile.TemporaryDirectory() as d:
            root, manifest = _manifest_tree(Path(d), _manifest_v1())
            accepted_digest, accepted = self._projection(root)
            altered = dict(accepted)
            altered["manifest_projection_bytes"] = accepted["manifest_projection_bytes"] + b" "
            index_bytes, _records = rpp.load_listed_records(root)
            renderer = rpp.read_bounded_regular_file(Path(rpp.__file__))
            self.assertNotEqual(
                accepted_digest,
                rpp.compute_projection_digest(index_bytes, [altered], renderer, BUILD),
            )

            poison = _manifest_v1(rule_text="POISON_ONE", anchor="POISON_A")
            manifest.write_text(json.dumps(poison), encoding="utf-8")
            mismatch_one, record_one = self._projection(root)
            poison["rules"]["axis-a"][0]["text"] = "POISON_TWO"
            manifest.write_text(json.dumps(poison), encoding="utf-8")
            mismatch_two, record_two = self._projection(root)
            self.assertEqual(record_one["manifest_snapshot"]["state"], "digest-mismatch")
            self.assertEqual(record_two["manifest_snapshot"]["state"], "digest-mismatch")
            self.assertEqual(mismatch_one, mismatch_two)
            self.assertNotEqual(accepted_digest, mismatch_one)


def _write_publication(root: Path, source_commit: str = BUILD) -> Path:
    out = root / "site" / "index.html"
    rc = rpp.main(["--root", str(root), "--out", str(out), "--source-commit", source_commit])
    if rc != 0:
        raise rpp.PublicationError("generate exited %s" % rc)
    return out


def _check_publication(root: Path, out: Path, source_commit: str = BUILD) -> None:
    rc = rpp.main(
        ["--root", str(root), "--out", str(out), "--source-commit", source_commit, "--check"]
    )
    if rc != 0:
        raise rpp.PublicationError("check exited %s" % rc)


def _regular_stats(site: Path) -> dict[Path, os.stat_result]:
    return {p: p.stat() for p in site.rglob("*") if p.is_file() and not p.is_symlink()}


class FirstRedDeepLinks(unittest.TestCase):
    """Issue #38 first RED: one survived and one silent resolve with exact state."""

    def test_survived_and_silent_deep_links_carry_exact_state(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            files = _site(root)
            self.assertIn("index.html", files)
            self.assertIn(RUN, files)
            self.assertIn(SURVIVED, files)
            self.assertIn(SILENT, files)
            self.assertNotIn("runs/%s/rules/0002.html" % REC, files)
            self.assertNotIn("runs/%s/rules/0003.html" % REC, files)

            overview = _text(files, "index.html")
            self.assertIn('href="runs/%s/"' % REC, overview)
            self.assertNotIn("<script", overview.lower())

            run_page = _text(files, RUN)
            self.assertIn("survived-rule", run_page)
            self.assertIn("silent-rule", run_page)
            self.assertIn('href="rules/0000.html"', run_page)
            self.assertIn('href="rules/0001.html"', run_page)
            self.assertIn("../../index.html", run_page)
            self.assertNotIn("killed-rule", run_page)
            self.assertNotIn("CONTROL keep path", run_page)

            report_doc = json.loads(
                (SURVIVED_SILENT / "report.v0.json").read_text(encoding="utf-8")
            )
            survived_how = report_doc["mutants"][0]["how"]
            silent_how = report_doc["mutants"][1]["how"]
            self.assertEqual(survived_how, "no vector distinguishes the survived rule")
            self.assertEqual(silent_how, "diagnostic moved, declared outcome did not")

            survived = _text(files, SURVIVED)
            silent = _text(files, SILENT)
            self.assertIn("survived-rule", survived)
            self.assertIn(">survived<", survived)
            self.assertIn(ca.SURVIVED_OBLIGATION, survived)
            self.assertNotIn(survived_how, survived)
            self.assertNotIn(ca.SILENT_OBLIGATION, survived)
            self.assertIn("axis-a", survived)

            self.assertIn("silent-rule", silent)
            self.assertIn(">silent<", silent)
            self.assertIn(ca.SILENT_OBLIGATION, silent)
            self.assertNotIn(silent_how, silent)
            self.assertNotIn(ca.SURVIVED_OBLIGATION, silent)
            self.assertIn("moved_diagnostic", silent)
            self.assertIn(">2<", silent)

            raw = "%s/%s/measurements/%s/report.v0.json" % (rpp.RAW_PREFIX, BUILD, REC)
            review = "%s/%s/measurements/%s/PROVENANCE.md" % (rpp.BLOB_PREFIX, BUILD, REC)
            source = "https://github.com/example/survived-silent/commit/" + ("a" * 40)
            for page, back in (
                (run_page, "../../index.html"),
                (survived, "../../../index.html"),
                (silent, "../../../index.html"),
            ):
                self.assertIn(raw, page)
                self.assertIn(review, page)
                self.assertIn(source, page)
                self.assertIn(back, page)
                self.assertNotIn("<script", page.lower())
                self.assertNotIn("javascript:", page.lower())

            projected = ca.survivor_findings(
                json.loads((SURVIVED_SILENT / "report.v0.json").read_text())
            )
            self.assertEqual(projected["finding_count"], 2)


class ActionableBinding(unittest.TestCase):
    def test_unconsumed_survivor_finding_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            orig = rpp.survivor_findings

            def extra(report, manifest=None):
                doc = orig(report, manifest=manifest)
                findings = list(doc["findings"])
                findings.append(
                    {
                        "rule": "ghost-rule",
                        "group": "axis-a",
                        "verdict": "survived",
                        "moved": 0,
                        "moved_diagnostic": 0,
                        "obligation": ca.SURVIVED_OBLIGATION,
                    }
                )
                out = dict(doc)
                out["findings"] = findings
                return out

            with mock.patch.object(rpp, "survivor_findings", extra):
                with self.assertRaises(rpp.PublicationError) as cm:
                    _site(root)
            self.assertIn("leftover", str(cm.exception).lower())

    def test_missing_how_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            report = root / "measurements" / REC / "report.v0.json"
            doc = json.loads(report.read_text(encoding="utf-8"))
            del doc["mutants"][0]["how"]
            report.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
            _write_index(root)
            with self.assertRaises(rpp.PublicationError) as cm:
                _site(root)
            self.assertIn("how", str(cm.exception).lower())


class CheckInventory(unittest.TestCase):
    def test_check_fails_missing_stale_and_surplus_without_writing(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            out = _write_publication(root)
            silent = root / "site" / "runs" / REC / "rules" / "0001.html"
            self.assertTrue(silent.is_file())

            missing = silent.read_bytes()
            silent.unlink()
            with self.assertRaises(rpp.PublicationError):
                _check_publication(root, out)
            self.assertFalse(silent.exists())
            silent.write_bytes(missing)

            stale = root / "site" / "runs" / REC / "index.html"
            stale.write_bytes(stale.read_bytes() + b"\n")
            with self.assertRaises(rpp.PublicationError):
                _check_publication(root, out)
            stale.write_bytes(stale.read_bytes()[:-1])

            surplus = root / "site" / "runs" / REC / "rules" / "9999.html"
            surplus.write_bytes(b"<html>surplus</html>\n")
            with self.assertRaises(rpp.PublicationError):
                _check_publication(root, out)
            surplus.unlink()

            out.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            before = _regular_stats(root / "site")
            _check_publication(root, out)
            after = _regular_stats(root / "site")
            self.assertEqual(set(before), set(after))
            for path, st in before.items():
                now = after[path]
                self.assertEqual(st.st_mtime_ns, now.st_mtime_ns)
                self.assertEqual(st.st_ino, now.st_ino)
                self.assertEqual(st.st_size, now.st_size)

    @unittest.skipIf(not hasattr(os, "mkfifo"), "os.mkfifo is unavailable")
    def test_surplus_fifo_fails_closed_without_opening(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            out = _write_publication(root)
            pipe = root / "site" / "runs" / REC / "rules" / "fifo"
            os.mkfifo(pipe)
            opened = []
            real_open = os.open

            def wrapped_open(path, flags, *args, **kwargs):
                target = Path(path) if not isinstance(path, int) else None
                if target is not None and target == pipe:
                    opened.append(path)
                    raise _Blocked("site inventory opened a FIFO")
                return real_open(path, flags, *args, **kwargs)

            previous = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(
                _Blocked("site inventory blocked on a FIFO")
            ))
            signal.alarm(5)
            started = time.monotonic()
            try:
                with mock.patch.object(os, "open", wrapped_open):
                    with self.assertRaises(rpp.PublicationError) as cm:
                        _check_publication(root, out)
                elapsed = time.monotonic() - started
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous)
            self.assertEqual(opened, [])
            self.assertLess(elapsed, 1.0)
            self.assertRegex(str(cm.exception).lower(), r"regular|special|fifo|symlink")
            self.assertTrue(stat.S_ISFIFO(pipe.lstat().st_mode))

    def test_generate_refuses_owned_surplus_and_leaves_cname(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            site = root / "site"
            site.mkdir()
            cname = site / "CNAME"
            cname.write_bytes(b"example.test\n")
            leftover = site / "runs" / REC / "rules" / "9999.html"
            leftover.parent.mkdir(parents=True)
            leftover.write_bytes(b"<html>old</html>\n")
            out = site / "index.html"
            self.assertFalse(out.exists())
            with self.assertRaises(rpp.PublicationError) as cm:
                rpp.main(["--root", str(root), "--out", str(out), "--source-commit", BUILD])
            self.assertIn("surplus", str(cm.exception).lower())
            self.assertFalse(out.exists())
            self.assertEqual(cname.read_bytes(), b"example.test\n")
            self.assertEqual(leftover.read_bytes(), b"<html>old</html>\n")

            leftover.unlink()
            self.assertEqual(
                rpp.main(["--root", str(root), "--out", str(out), "--source-commit", BUILD]),
                0,
            )
            self.assertTrue(out.is_file())
            self.assertEqual(cname.read_bytes(), b"example.test\n")
            self.assertFalse(leftover.exists())
            _check_publication(root, out)

    def test_unowned_regular_outside_cname_fails_generate_and_check_without_write(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            site = root / "site"
            site.mkdir()
            extra = site / "extra.html"
            extra.write_bytes(b"<html>unowned</html>\n")
            out = site / "index.html"
            with self.assertRaises(rpp.PublicationError) as cm:
                rpp.main(["--root", str(root), "--out", str(out), "--source-commit", BUILD])
            self.assertIn("surplus", str(cm.exception).lower())
            self.assertIn("extra.html", str(cm.exception))
            self.assertFalse(out.exists())
            self.assertEqual(extra.read_bytes(), b"<html>unowned</html>\n")

            extra.unlink()
            self.assertEqual(
                rpp.main(["--root", str(root), "--out", str(out), "--source-commit", BUILD]),
                0,
            )
            rogue = site / "rogue.js"
            rogue.write_bytes(b"alert(1)\n")
            out.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            before = _regular_stats(site)
            with self.assertRaises(rpp.PublicationError) as check_cm:
                _check_publication(root, out)
            self.assertIn("surplus", str(check_cm.exception).lower())
            self.assertIn("rogue.js", str(check_cm.exception))
            after = _regular_stats(site)
            self.assertEqual(set(before), set(after))
            for path, st in before.items():
                now = after[path]
                self.assertEqual(st.st_mtime_ns, now.st_mtime_ns)
                self.assertEqual(st.st_ino, now.st_ino)
                self.assertEqual(st.st_size, now.st_size)

    def test_existing_tmp_regular_is_surplus_without_write(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            site = root / "site"
            site.mkdir()
            leftover = site / "rogue.js.tmp"
            leftover.write_bytes(b"alert(1)\n")
            out = site / "index.html"
            with self.assertRaises(rpp.PublicationError) as cm:
                rpp.main(["--root", str(root), "--out", str(out), "--source-commit", BUILD])
            self.assertIn("surplus", str(cm.exception).lower())
            self.assertIn("rogue.js.tmp", str(cm.exception))
            self.assertFalse(out.exists())
            self.assertEqual(leftover.read_bytes(), b"alert(1)\n")

    def test_regular_file_named_runs_fails_generate_before_write(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            site = root / "site"
            site.mkdir()
            collision = site / "runs"
            collision.write_bytes(b"not a directory\n")
            out = site / "index.html"
            with self.assertRaises(rpp.PublicationError) as cm:
                rpp.main(["--root", str(root), "--out", str(out), "--source-commit", BUILD])
            self.assertRegex(str(cm.exception).lower(), r"surplus|runs")
            self.assertFalse(out.exists())
            self.assertTrue(collision.is_file())
            self.assertEqual(collision.read_bytes(), b"not a directory\n")


class NonActionableAndDiagnostics(unittest.TestCase):
    def test_controls_and_killed_do_not_get_rule_pages(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [VALID / "report.v0.json"])
            files = _site(root)
            rec_id = "valid-tersign"
            self.assertIn("runs/%s/index.html" % rec_id, files)
            self.assertIn("runs/%s/rules/0000.html" % rec_id, files)
            self.assertIn("runs/%s/rules/0013.html" % rec_id, files)
            rule_pages = [rel for rel in files if rel.startswith("runs/%s/rules/" % rec_id)]
            self.assertEqual(len(rule_pages), 2)
            run_page = _text(files, "runs/%s/index.html" % rec_id)
            self.assertNotIn("CONTROL tighten", run_page)
            self.assertNotIn("moved_diagnostic", run_page)
            survived = _text(files, "runs/%s/rules/0000.html" % rec_id)
            self.assertNotIn("moved_diagnostic", survived)


def _escaped_ceilings() -> tuple[str, ...]:
    return tuple(html.escape(line, quote=True) for line in rpp.CEILING_LINES)


class PublicClaimsOnDeepPages(unittest.TestCase):
    def test_run_and_rule_pages_carry_all_four_ceilings(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            files = _site(root)
            for rel in (RUN, SURVIVED, SILENT):
                page = _text(files, rel)
                for line in _escaped_ceilings():
                    self.assertIn(line, page)
                self.assertIn('class="non-claims"', page)

    def test_run_page_keeps_typed_counts_and_silent_label(self):
        live = _site(REPO_ROOT)
        tersign = _text(live, "runs/tersign-1cc5ea32/index.html")
        self.assertIn('aria-label="silent not measured"', tersign)
        self.assertIn("survived 1", tersign)
        self.assertIn('aria-label="diagnostic_channel_declared not declared"', tersign)
        self.assertIn('class="counts"', tersign)

        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            run_page = _text(_site(root), RUN)
            self.assertIn('aria-label="silent 1"', run_page)
            self.assertNotIn('aria-label="silent not measured"', run_page)
            self.assertIn('aria-label="diagnostic_channel_declared declared"', run_page)
            self.assertIn("survived 1", run_page)
            self.assertIn("killed 1", run_page)
            self.assertIn("control_status killed", run_page)


class KeyboardAndMobile(unittest.TestCase):
    def test_shared_css_and_landmarks_on_detail_pages(self):
        with tempfile.TemporaryDirectory() as d:
            root = _write_tree(Path(d), [SURVIVED_SILENT / "report.v0.json"])
            files = _site(root)
            for rel in ("index.html", RUN, SURVIVED):
                page = _text(files, rel)
                self.assertIn("overflow-x: hidden", page)
                self.assertIn("width: min(100%, 390px)", page)
                self.assertIn("overflow-wrap: anywhere", page)
                self.assertIn("a:focus", page)
                self.assertIn("Skip to", page)
                self.assertIn("<main", page)
                self.assertIn("<header", page)
                self.assertNotIn("<script", page.lower())


if __name__ == "__main__":
    unittest.main(verbosity=1)
