#!/usr/bin/env python3
"""A report records the manifest path it is handed, so no host path may reach a page (#204).

Runs no candidate, no Docker and no PREPARE. The facade test replaces the driver with a recorder
that stops the run at the moment it would start.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "measurements"), str(ROOT / "scripts"),
              str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import owned_slice_b_local as slice_b  # noqa: E402
import render_publication_page as rpp  # noqa: E402
from test_publication_page import VALID, _write_tree  # noqa: E402

# The two retained reports that predate the fix. Their README discloses the path; they stay as
# retained bytes and are never published. Nothing may join this list.
DISCLOSED_HOST_PATHS = (
    "measurements/owned-slice-b-5918ec4/declared/report.v0.json",
    "measurements/owned-slice-b-5918ec4/independent/report.v0.json",
)


def _completed_tree(tmp: Path, manifest: str) -> Path:
    staged = tmp / "staged" / VALID.name
    shutil.copytree(VALID, staged)
    report = staged / "report.v0.json"
    doc = json.loads(report.read_text(encoding="utf-8"))
    doc["manifest"] = manifest
    report.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    root = _write_tree(tmp, [report])
    return root / "measurements" / VALID.name / "report.v0.json"


class TheRendererRefusesAHostPath(unittest.TestCase):
    def test_a_repository_relative_manifest_loads(self):
        with tempfile.TemporaryDirectory() as d:
            path = _completed_tree(Path(d), "measurements/tersign-1cc5ea32/manifest.json")
            self.assertEqual(rpp.load_record(path)["doc"]["manifest"],
                             "measurements/tersign-1cc5ea32/manifest.json")

    def test_a_host_path_or_an_absolute_path_is_refused(self):
        for manifest in ("/Users/someone/worktree/measurements/x/manifest.json",
                         "/home/runner/work/measurements/x/manifest.json",
                         "/private/tmp/x/manifest.json",
                         "/opt/elsewhere/manifest.json",
                         "C:\\\\work\\\\manifest.json"):
            with self.subTest(manifest=manifest):
                with tempfile.TemporaryDirectory() as d:
                    path = _completed_tree(Path(d), manifest)
                    with self.assertRaisesRegex(rpp.PublicationError, "^manifest contains"):
                        rpp.load_record(path)


class RetainedReports(unittest.TestCase):
    def _retained(self):
        return sorted(p.relative_to(ROOT).as_posix()
                      for p in (ROOT / "measurements").rglob("report.v0.json"))

    def test_every_retained_report_is_portable_except_the_disclosed_pair(self):
        for rel in self._retained():
            manifest = json.loads((ROOT / rel).read_text(encoding="utf-8"))["manifest"]
            with self.subTest(report=rel):
                if rel in DISCLOSED_HOST_PATHS:
                    with self.assertRaises(rpp.PublicationError):
                        rpp._require_portable_public_text(manifest, field="manifest")
                else:
                    rpp._require_portable_public_text(manifest, field="manifest")

    def test_the_disclosed_pair_is_still_there_and_still_disclosed(self):
        """If the pair is ever removed or replaced, this list must shrink with it."""
        for rel in DISCLOSED_HOST_PATHS:
            self.assertIn(rel, self._retained())
        readme = (ROOT / "measurements" / "owned-slice-b-5918ec4" / "README.md").read_text(
            encoding="utf-8")
        self.assertIn("#204", readme)


class TheFacadeHandsTheDriverARelativePath(unittest.TestCase):
    def test_run_starts_from_the_repository_root_with_the_relative_pins_directory(self):
        seen = {}

        class Stop(Exception):
            pass

        def recorder(**kwargs):
            seen.update(kwargs, cwd=os.getcwd())
            raise Stop()

        before = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "declared"
            base.mkdir()
            (base / slice_b.AUTHORIZE_FILENAME).write_bytes(b"{}")
            (base / slice_b.PREPARE_FILENAME).write_bytes(b"{}")
            # Start somewhere other than the repository root, or a facade that never changes
            # directory would look exactly like one that does: the suite runs from the root.
            os.chdir(d)
            try:
                with mock.patch.object(slice_b.driver, "run_authorized", side_effect=recorder):
                    with self.assertRaises(Stop):
                        slice_b.run("declared", Path(d))
                self.assertEqual(Path(os.getcwd()).resolve(), Path(d).resolve())
            finally:
                os.chdir(before)
        self.assertEqual(Path(seen["cwd"]).resolve(), ROOT.resolve())
        self.assertEqual(seen["pins_dir"].as_posix(), "measurements/owned-contained-v1")
        self.assertFalse(seen["pins_dir"].is_absolute())
        self.assertTrue(seen["materialize_dest"].is_absolute())
        self.assertTrue(seen["envelope_dest"].is_absolute())
        self.assertEqual(seen["root"], slice_b.ROOT)

    def test_a_relative_out_directory_stays_where_the_operator_meant_it(self):
        """The run changes into the repository root. A relative --out resolved after that would
        put the materialized tree inside the repository, so it is resolved first."""
        seen = {}

        class Stop(Exception):
            pass

        def recorder(**kwargs):
            seen.update(kwargs)
            raise Stop()

        before = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            work = Path(d).resolve()
            base = work / "out" / "declared"
            base.mkdir(parents=True)
            (base / slice_b.AUTHORIZE_FILENAME).write_bytes(b"{}")
            (base / slice_b.PREPARE_FILENAME).write_bytes(b"{}")
            os.chdir(work)
            try:
                with mock.patch.object(slice_b.driver, "run_authorized", side_effect=recorder):
                    with self.assertRaises(Stop):
                        slice_b.run("declared", Path("out"))
            finally:
                os.chdir(before)
            self.assertEqual(seen["materialize_dest"], base / "materialize")
            self.assertNotIn(ROOT.resolve(), seen["materialize_dest"].parents)

    def test_the_relative_pins_directory_names_the_same_bytes(self):
        for selection in slice_b.SELECTIONS:
            contract = slice_b.contract_for(selection)
            self.assertEqual((ROOT / slice_b.pins_relpath(contract)).resolve(),
                             slice_b.pins_dir(contract).resolve())


if __name__ == "__main__":
    unittest.main()
