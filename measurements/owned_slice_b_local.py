#!/usr/bin/env python3
"""Fixed local facade for Slice B of #169 (#199): the declared and the independent selection.

It drives the existing sealed route for exactly two code-owned contracts, selected by name from a
closed pair, under `contained-oci-v1` on the operator's own Docker. It has no hosted path, no
packet, no dispatch and no free contract parameter. Its output is local evidence, not hosted
containment proof.

Commands (each writes under `--out/<selection>/`, refusing to overwrite):

- `prepare <selection>`: PREPARE v2 for that contract (builds the inert probe; materializes the
  pinned candidate and corpus).
- `authorize <selection>`: `authorize.v0` over those PREPARE bytes.
- `run <selection>`: the sealed driver; writes `report.v0.json` and the effective-envelope
  collection.
- `provenance`: the independent selection's `class-provenance.v0` from the frozen bytes.
- `derive-class`: the independent selection's `class-attempt.v0`, derived from the validated
  report, with the PREPARE bytes as the environment artifact.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _entry in (str(ROOT), str(ROOT / "measurements")):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

import aee_checker_sealed_authorize as authorize  # noqa: E402
import aee_checker_sealed_driver as driver  # noqa: E402
import aee_checker_sealed_run as sealed_run  # noqa: E402
import corpus_adequacy as ca  # noqa: E402
from aee_checker_sealed_common import PrepareError  # noqa: E402
from aee_checker_sealed_materialize import tree_sha256  # noqa: E402
from sealed_measurement_contract import (  # noqa: E402
    OWNED_CONTAINED_V1_CONTRACT,
    OWNED_INDEPENDENT_V0_CONTRACT,
)

PROFILE = "contained-oci-v1"
SELECTIONS = {
    "declared": OWNED_CONTAINED_V1_CONTRACT,
    "independent": OWNED_INDEPENDENT_V0_CONTRACT,
}
REPOSITORY = "corpus-adequacy/corpus-adequacy"
# The commit that froze the independent selection (Slice A) and its two files.
SELECTION_COMMIT = "9a73f1c0ab29856443d0a6c6f8fb19bf70989cc8"
SELECTION_FILES = ("manifest.json", "mutation-bundle.json")
CLASS_ID = "owned-independent-v0"
ATTEMPT_ID = "owned-independent-v0-slice-b-01"
PREPARE_FILENAME = "prepare.v2.json"
AUTHORIZE_FILENAME = "authorize.v0.json"
REPORT_FILENAME = "report.v0.json"
COLLECTION_DIRNAME = "effective-envelope-collection.v0"
PROVENANCE_FILENAME = "class-provenance.v0.json"
ATTEMPT_FILENAME = "class-attempt.v0.json"


class SliceBError(Exception):
    """A named refusal. Nothing is overwritten."""


def contract_for(selection: str):
    if selection not in SELECTIONS:
        raise SliceBError("selection")
    return SELECTIONS[selection]


def pins_dir(contract) -> Path:
    return ROOT.joinpath(*contract.pins_relpath)


def _new_file(path: Path, raw: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise SliceBError("exists:%s" % path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def _read(path: Path) -> bytes:
    try:
        return ca.read_bounded_regular_file(path)
    except ca.ManifestError as exc:
        raise SliceBError("read:%s" % path.name) from exc


def prepare(selection: str, out: Path) -> dict:
    contract = contract_for(selection)
    dest = Path(out) / selection / "prepare"
    raw = sealed_run.prepare(
        pins_dir(contract), dest, root=ROOT, adapter=ROOT / contract.adapter_relpath,
        schema=sealed_run.PREPARE_V2_SCHEMA, contract=contract)
    target = Path(out) / selection / PREPARE_FILENAME
    _new_file(target, raw)
    return {"selection": selection, "prepare_sha256": hashlib.sha256(raw).hexdigest()}


def authorize_selection(selection: str, out: Path) -> dict:
    contract = contract_for(selection)
    base = Path(out) / selection
    prepare_raw = _read(base / PREPARE_FILENAME)
    target = base / AUTHORIZE_FILENAME
    if target.exists() or target.is_symlink():
        raise SliceBError("exists:%s" % target.name)
    raw = authorize.emit_authorize_v0(prepare_raw, target, contract=contract)
    return {"selection": selection, "authorize_sha256": hashlib.sha256(raw).hexdigest()}


def run(selection: str, out: Path) -> dict:
    contract = contract_for(selection)
    base = Path(out) / selection
    report_path = base / REPORT_FILENAME
    if report_path.exists() or (base / COLLECTION_DIRNAME).exists():
        raise SliceBError("exists:%s" % REPORT_FILENAME)
    report = driver.run_authorized(
        authorize_raw=_read(base / AUTHORIZE_FILENAME),
        prepare_raw=_read(base / PREPARE_FILENAME),
        pins_dir=pins_dir(contract), materialize_dest=base / "materialize",
        root=ROOT, execution_profile=PROFILE,
        envelope_dest=base / COLLECTION_DIRNAME, contract=contract)
    raw = ca.encode_report_v0(report)
    _new_file(report_path, raw)
    return {"selection": selection, "report_sha256": hashlib.sha256(raw).hexdigest(),
            "killed": report.get("killed"), "survived": report.get("survived"),
            "control_status": report.get("control_status"),
            "unproved": report.get("unproved"), "adequate": report.get("adequate")}


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def observation_declaration_sha256(manifest_raw: bytes) -> str:
    """Canonical digest of what is observed: the manifest without its selection fields."""
    doc = json.loads(manifest_raw.decode("utf-8"))
    for key in ("mutants", "default_group"):
        doc.pop(key, None)
    return _digest((json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True)
                    + "\n").encode("utf-8"))


def _selection_tree_sha256() -> str:
    """Tree digest of the two frozen files as committed at the selection commit."""
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        for name in SELECTION_FILES:
            blob = subprocess.run(
                ["git", "-C", str(ROOT), "show",
                 "%s:measurements/owned-independent-v0/%s" % (SELECTION_COMMIT, name)],
                capture_output=True, check=True).stdout
            (root / name).write_bytes(blob)
        return "sha256:" + tree_sha256(root)


def build_provenance() -> dict:
    contract = OWNED_INDEPENDENT_V0_CONTRACT
    manifest_raw = _read(pins_dir(contract) / "manifest.json")
    bundle_raw = _read(pins_dir(contract) / "mutation-bundle.json")
    bundle = json.loads(bundle_raw.decode("utf-8"))
    manifest = json.loads(manifest_raw.decode("utf-8"))
    ordinary = [row for row in manifest["mutants"][contract.mutation_group]
                if not row.get("control")]
    if len(ordinary) != 1 or ordinary[0]["id"] != contract.site_ids[0]:
        raise SliceBError("selection_shape")
    authoring = bundle["authoring"]
    freeze = bundle["candidate_freeze"]
    if freeze["source_commit"] != contract.instrument_commit:
        raise SliceBError("freeze_commit")
    bundle_digest = _digest(bundle_raw)
    return {
        "schema": ca.CLASS_PROVENANCE_SCHEMA,
        "class_id": CLASS_ID,
        "requested_class": "independent",
        "manifest_sha256": _digest(manifest_raw),
        "mutation_bundle_sha256": bundle_digest,
        "candidate_freeze": {
            "candidate": {"repository": REPOSITORY, "commit": contract.instrument_commit,
                          "tree_sha256": "sha256:" + contract.subject_tree_sha256},
            "corpus": {"repository": REPOSITORY, "commit": contract.instrument_commit,
                       "tree_sha256": "sha256:" + contract.corpus_tree_sha256},
            "observation_declaration_sha256": observation_declaration_sha256(manifest_raw),
        },
        "authoring": {
            "mutation_author": authoring["mutation_author"],
            "candidate_builder": authoring["candidate_builder"],
            "relationship": authoring["relationship"],
            "candidate_outcomes_seen": authoring["candidate_outcomes_seen"],
        },
        # The candidate froze before the selection was written, so only the commit event is
        # true; a held-out chain here would be a false record.
        "visibility_events": [{
            "ordinal": 0,
            "event": "selection-committed",
            "mutation_bundle_sha256": bundle_digest,
            "actor": authoring["mutation_author"],
            "predecessor_event_sha256": None,
        }],
        "origin": {"kind": "authored", "source": {
            "repository": REPOSITORY, "commit": SELECTION_COMMIT,
            "tree_sha256": _selection_tree_sha256()}},
        # The bound observation channel for the one ordinary mutation, not a predicted kill.
        "expected_distinctions": [{
            "group": contract.mutation_group, "label": ordinary[0]["label"],
            "channel": "outcome", "member": "rows"}],
        "non_claims": list(ca.CLASS_NON_CLAIMS),
    }


@contextlib.contextmanager
def manifest_beside_subject():
    """The frozen manifest next to a copy of the pinned candidate source, as its `repo_root`
    expects, so the class loaders can bind the declared implementation file."""
    contract = OWNED_INDEPENDENT_V0_CONTRACT
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        shutil.copyfile(pins_dir(contract) / "manifest.json", root / "manifest.json")
        shutil.copytree(ROOT / contract.subject_subdir, root / "subject")
        yield root / "manifest.json"


def write_provenance(out: Path) -> dict:
    raw = ca.encode_class_provenance_v0(build_provenance())
    target = Path(out) / "independent" / PROVENANCE_FILENAME
    contract = OWNED_INDEPENDENT_V0_CONTRACT
    with tempfile.TemporaryDirectory() as check_dir:
        staged = Path(check_dir) / PROVENANCE_FILENAME
        staged.write_bytes(raw)
        with manifest_beside_subject() as manifest_path:
            ca.load_class_provenance_v0(
                staged, manifest_path=manifest_path,
                mutation_bundle_path=pins_dir(contract) / "mutation-bundle.json")
    _new_file(target, raw)
    return {"provenance_sha256": hashlib.sha256(raw).hexdigest()}


def derive_class(out: Path) -> dict:
    contract = OWNED_INDEPENDENT_V0_CONTRACT
    base = Path(out) / "independent"
    doc = ca.derive_class_attempt_v0(
        attempt_id=ATTEMPT_ID,
        provenance_raw=_read(base / PROVENANCE_FILENAME),
        manifest_raw=_read(pins_dir(contract) / "manifest.json"),
        report_raw=_read(base / REPORT_FILENAME),
        environment_raw=_read(base / PREPARE_FILENAME),
        predecessor=None)
    raw = ca.encode_class_attempt_v0(doc)
    target = base / ATTEMPT_FILENAME
    with tempfile.TemporaryDirectory() as check_dir:
        staged = Path(check_dir) / ATTEMPT_FILENAME
        staged.write_bytes(raw)
        with manifest_beside_subject() as manifest_path:
            loaded = ca.load_class_attempt_v0(
                staged, provenance_path=base / PROVENANCE_FILENAME,
                manifest_path=manifest_path,
                report_path=base / REPORT_FILENAME, environment_path=base / PREPARE_FILENAME)
    _new_file(target, raw)
    return {"attempt_sha256": hashlib.sha256(raw).hexdigest(),
            "status": loaded["status"], "effective_class": loaded["effective_class"],
            "visibility_status": loaded["visibility_status"]}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="owned_slice_b_local")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "authorize", "run"):
        command = sub.add_parser(name)
        command.add_argument("selection", choices=sorted(SELECTIONS))
        command.add_argument("--out", required=True)
    for name in ("provenance", "derive-class"):
        command = sub.add_parser(name)
        command.add_argument("--out", required=True)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    out = Path(args.out)
    try:
        if args.command == "prepare":
            result = prepare(args.selection, out)
        elif args.command == "authorize":
            result = authorize_selection(args.selection, out)
        elif args.command == "run":
            result = run(args.selection, out)
        elif args.command == "provenance":
            result = write_provenance(out)
        else:
            result = derive_class(out)
    except (SliceBError, PrepareError, authorize.AuthorizeError, driver.DriverError,
            ca.ManifestError, subprocess.CalledProcessError, OSError) as exc:
        print("slice b refused: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
