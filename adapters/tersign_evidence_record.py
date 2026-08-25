#!/usr/bin/env python3
"""Pinned Tersign evidence-record format adapter. Standard library only.

Converts one exact upstream checkout into files the existing process runner
can consume. Kind stays metadata. The typed outcome is (expect, reason|null).
Does not import or execute verify.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
import corpus_adequacy as ca  # noqa: E402
import isolated_tree as iso  # noqa: E402

SOURCE_SCHEMA = "corpus-adequacy.tersign-evidence-record.source.v0"
PIN_REPOSITORY = "tersignhq/evidence-record-conformance"
PIN_COMMIT = "1cc5ea32b3da4f195b55782c8a3573d8564673a7"
PIN_MANIFEST_SHA256 = "5a3ed06d0335a803cce44257339661ee75fd902e829219277c68917abf897690"
PIN_VECTORS_TREE = "d84527932ee96004b9cf6329d554eb7e039e5221"
PIN_VECTORS_FILES_SHA256 = "94fb09e17aa63bd0f71044ba21964ae45cb6eed41a88d4d4363f72c5d86dfea8"
PIN_LICENSE = "Apache-2.0"
PINNED_KINDS = frozenset({
    "anchor_relation", "boundary_binding", "canonical_bytes", "chain_link",
    "chain_set", "decision_evidence_binding", "digest_recompute",
    "independence_claim", "offer_binding", "phase_claim",
})
PINNED_REASONS = frozenset({
    "binding_reject", "boundary_reject", "canonicalization_reject",
    "completeness_reject", "continuity_reject", "existence_reject",
    "independence_reject", "number_domain_reject", "phase_reject",
    "recompute_mismatch",
})
OLD_MANIFEST_KEYS = frozenset({
    "anchor_relation", "canonicalization", "chain_link", "chain_set",
    "content_address", "decision_evidence_binding", "identifier_normalization",
    "layer", "offer_binding", "profile", "suite", "vectors", "version",
})
NEW_MANIFEST_KEYS = OLD_MANIFEST_KEYS | frozenset({
    "commitment_derivation", "field_naming", "witnessed_inclusion",
})
BODY_KEYS = frozenset({
    "id", "kind", "expect", "input", "description", "reason", "provenance",
})
VECTORS_DIGEST_TAG = b"tersign-evidence-record.vectors.v0\n"


class PinProfile(NamedTuple):
    repository: str
    commit: str
    manifest_sha256: str
    vectors_tree: str
    vectors_files_sha256: str
    license: str
    manifest_keys: frozenset[str]
    kinds: frozenset[str]
    reasons: frozenset[str]
    counts: tuple[int, int, int]


PIN_PROFILES = (
    PinProfile(
        repository=PIN_REPOSITORY,
        commit=PIN_COMMIT,
        manifest_sha256=PIN_MANIFEST_SHA256,
        vectors_tree=PIN_VECTORS_TREE,
        vectors_files_sha256=PIN_VECTORS_FILES_SHA256,
        license=PIN_LICENSE,
        manifest_keys=OLD_MANIFEST_KEYS,
        kinds=PINNED_KINDS,
        reasons=PINNED_REASONS,
        counts=(54, 22, 32),
    ),
    PinProfile(
        repository="tersignhq/evidence-record-conformance",
        commit="0e560c1ad47f08177042c62754ebe6e0b482ad9a",
        manifest_sha256="40abdf703b3b731c685142aa24a2561f1cc4679a013d51fdcb9764a1658819c6",
        vectors_tree="fecf642073dd6b971aebba52bb67153efb1a1dfe",
        vectors_files_sha256="f4244e4bbcb86126f70cd4750d0a6ce8c729a0ef9baca428fdea9929dc97afd3",
        license="Apache-2.0",
        manifest_keys=NEW_MANIFEST_KEYS,
        kinds=PINNED_KINDS,
        reasons=PINNED_REASONS,
        counts=(60, 25, 35),
    ),
)


class AdapterError(Exception):
    """The pinned source cannot be adapted."""


def _wrap(exc: BaseException) -> AdapterError:
    return AdapterError(str(exc))


def _load_bytes(path: Path) -> bytes:
    try:
        return ca.read_bounded_regular_file(path)
    except ca.ManifestError as exc:
        raise _wrap(exc) from exc


def _load_json(path: Path):
    raw = _load_bytes(path)
    try:
        return raw, ca._parse_projection_json(raw)
    except (ca.ManifestError, json.JSONDecodeError) as exc:
        raise _wrap(exc) from exc


def _hex_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _vectors_files_digest(files: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    digest.update(VECTORS_DIGEST_TAG)
    for name, data in files:
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _encode(doc: dict) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _require_basename(name: str, where: str) -> str:
    if not name or name != Path(name).name:
        raise AdapterError("%s is not a single basename: %r" % (where, name))
    if "/" in name or "\\" in name or "\x00" in name:
        raise AdapterError("%s contains an unsafe path character: %r" % (where, name))
    if ":" in name:
        raise AdapterError("%s contains an NTFS stream separator: %r" % (where, name))
    return name


def _git_ids(source: Path) -> tuple[str | None, str | None]:
    if not (source / ".git").exists():
        return None, None
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"

    def show(rev: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(source), "rev-parse", rev],
            capture_output=True, timeout=10, env=env, text=True)
        if proc.returncode != 0:
            raise AdapterError("could not resolve %s in %s" % (rev, source))
        return proc.stdout.strip()

    return show("HEAD"), show("HEAD:vectors")


def _scandir_regular_names(directory: Path) -> list[str]:
    names = []
    try:
        entries = os.scandir(directory)
    except OSError as exc:
        raise AdapterError("could not read %s: %s" % (directory, exc)) from exc
    with entries:
        for entry in entries:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise AdapterError("could not lstat %s: %s" % (entry.path, exc)) from exc
            if stat.S_ISLNK(st.st_mode):
                raise AdapterError("symlink refused: %s" % entry.path)
            if not stat.S_ISREG(st.st_mode):
                raise AdapterError("not a regular file: %s" % entry.path)
            names.append(entry.name)
    return names


def _require_empty_dest(dest: Path) -> None:
    try:
        st = dest.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise AdapterError("destination is a symlink: %s" % dest)
    if not stat.S_ISDIR(st.st_mode):
        raise AdapterError("destination is not a directory: %s" % dest)
    if _scandir_regular_names(dest) or any(dest.iterdir()):
        raise AdapterError("destination is not empty: %s" % dest)


def _entry_reason(entry: dict, where: str, profile: PinProfile) -> str | None:
    expect = entry.get("expect")
    if expect not in ("valid", "reject"):
        raise AdapterError("%s expect must be valid or reject" % where)
    keys = set(entry)
    allowed = {"file", "kind", "expect"}
    if expect == "reject":
        allowed.add("reason")
        if "reason" not in entry:
            raise AdapterError("%s reject is missing reason" % where)
        if entry["reason"] not in profile.reasons:
            raise AdapterError("%s has unknown reason %r" % (where, entry["reason"]))
        extra = keys - allowed
        if extra:
            raise AdapterError("%s has unknown fields %s" % (where, sorted(extra)))
        return entry["reason"]
    if "reason" in entry:
        raise AdapterError("%s valid entry must omit reason" % where)
    extra = keys - allowed
    if extra:
        raise AdapterError("%s has unknown fields %s" % (where, sorted(extra)))
    return None


def _select_profile(
        commit: str | None,
        tree: str | None,
        manifest_sha256: str,
        vectors_files_sha256: str) -> PinProfile:
    if (commit is None) != (tree is None):
        raise AdapterError("incomplete Git source identity")
    if commit is None:
        matches = [
            profile for profile in PIN_PROFILES
            if profile.manifest_sha256 == manifest_sha256
            and profile.vectors_files_sha256 == vectors_files_sha256
        ]
    else:
        matches = [
            profile for profile in PIN_PROFILES
            if profile.commit == commit
            and profile.manifest_sha256 == manifest_sha256
            and profile.vectors_tree == tree
            and profile.vectors_files_sha256 == vectors_files_sha256
        ]
    if len(matches) != 1:
        raise AdapterError(
            "source manifest/vector body digest identity does not match any allowed pin")
    return matches[0]


def adapt(source: Path, dest: Path) -> None:
    source = Path(source)
    dest = Path(dest)
    _require_empty_dest(dest)
    manifest_raw, manifest = _load_json(source / "MANIFEST.json")
    if not isinstance(manifest, dict):
        raise AdapterError("MANIFEST.json must be an object")
    if "vectors" not in manifest or not isinstance(manifest["vectors"], list):
        raise AdapterError("MANIFEST.json vectors must be an array")
    vectors_dir = source / "vectors"
    on_disk = set(_scandir_regular_names(vectors_dir))
    collected: list[tuple[str, bytes]] = []
    seen_files: set[str] = set()
    for i, entry in enumerate(manifest["vectors"]):
        where = "MANIFEST.json vectors[%d]" % i
        if not isinstance(entry, dict):
            raise AdapterError("%s must be an object" % where)
        filename = _require_basename(str(entry.get("file", "")), where + ".file")
        if filename in seen_files:
            raise AdapterError("duplicate manifest file %r" % filename)
        seen_files.add(filename)
        if filename not in on_disk:
            raise AdapterError("missing vector file %s" % filename)
        collected.append((filename, _load_bytes(vectors_dir / filename)))
    extra_files = sorted(on_disk - seen_files)
    if extra_files:
        raise AdapterError("unlisted files under vectors/: %s" % extra_files)
    commit, tree = _git_ids(source)
    profile = _select_profile(
        commit,
        tree,
        _hex_digest(manifest_raw),
        _vectors_files_digest(sorted(collected)),
    )
    extra_top = set(manifest) - profile.manifest_keys
    if extra_top:
        raise AdapterError("MANIFEST.json has unknown fields %s" % sorted(extra_top))

    rows = []
    seen_ids: set[str] = set()
    kinds = {}
    reasons = set()
    valid = reject = 0
    for i, (entry, collected_file) in enumerate(zip(manifest["vectors"], collected)):
        where = "MANIFEST.json vectors[%d]" % i
        filename, body_raw = collected_file
        kind = entry.get("kind")
        if kind not in profile.kinds:
            raise AdapterError("%s has unknown kind %r" % (where, kind))
        reason = _entry_reason(entry, where, profile)
        try:
            body = ca._parse_projection_json(body_raw)
        except (ca.ManifestError, json.JSONDecodeError) as exc:
            raise _wrap(exc) from exc
        if not isinstance(body, dict):
            raise AdapterError("%s body must be an object" % filename)
        extra_body = set(body) - BODY_KEYS
        if extra_body:
            raise AdapterError("%s has unknown fields %s" % (filename, sorted(extra_body)))
        vector_id = body.get("id")
        if not isinstance(vector_id, str) or not vector_id:
            raise AdapterError("%s is missing id" % filename)
        if filename != vector_id + ".json":
            raise AdapterError("%s filename does not match body id %r" % (filename, vector_id))
        if vector_id in seen_ids:
            raise AdapterError("duplicate body id %r" % vector_id)
        seen_ids.add(vector_id)
        if body.get("kind") != kind:
            raise AdapterError("%s body kind disagrees with the manifest" % filename)
        if body.get("expect") != entry.get("expect"):
            raise AdapterError("%s body expect disagrees with the manifest" % filename)
        body_reason = body.get("reason")
        if body_reason != reason:
            raise AdapterError("%s body reason disagrees with the manifest" % filename)
        if entry["expect"] == "valid":
            valid += 1
        else:
            reject += 1
            reasons.add(reason)
        kinds.setdefault(kind, set()).add(entry["expect"])
        rows.append({
            "authored_kind": kind,
            "expected_reason": reason,
            "expected_verdict": entry["expect"],
            "vector_id": vector_id,
            "vector_path": "cases/%s.json" % vector_id,
        })
    expected_vectors, expected_valid, expected_reject = profile.counts
    if (len(rows), valid, reject) != profile.counts:
        raise AdapterError(
            "observed counts %d/%d/%d do not match %d/%d/%d"
            % (len(rows), valid, reject,
               expected_vectors, expected_valid, expected_reject))
    if set(kinds) != profile.kinds:
        raise AdapterError("kind closure does not match the pin")
    if reasons != profile.reasons:
        raise AdapterError("reason closure does not match the pin")
    one_sided = sorted(k for k, vs in kinds.items() if vs != {"valid", "reject"})
    if one_sided:
        raise AdapterError("kinds missing both verdicts: %s" % one_sided)
    rows.sort(key=lambda row: row["vector_id"])
    source_doc = {
        "schema": SOURCE_SCHEMA,
        "repository": profile.repository,
        "commit": profile.commit,
        "manifest_sha256": profile.manifest_sha256,
        "vectors_tree": profile.vectors_tree,
        "license": profile.license,
        "counts": {
            "vectors": expected_vectors,
            "valid": expected_valid,
            "reject": expected_reject,
        },
        "kinds": sorted(profile.kinds),
        "reasons": sorted(profile.reasons),
        "source_validation": {
            "body_manifest_agreement": True,
            "closures_match_pin": True,
            "two_sided_per_kind": True,
        },
        "non_claims": [
            "This adapter preserves one pinned upstream corpus.",
            "It does not prove authenticity, endorsement, completeness, or correctness of upstream labels.",
            "It does not prove the upstream verifier or any Assay canonicalizer.",
            "Kind is source metadata, not an outcome.",
        ],
    }
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix="tersign-adapt-", dir=str(dest.parent)))
    try:
        cases = temp / "cases"
        cases.mkdir()
        for filename, data in collected:
            vector_id = filename[:-5]
            out = cases / (vector_id + ".json")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            fd = os.open(out, flags, 0o600)
            try:
                iso.write_all(fd, data)
            except iso.IsolationError as exc:
                raise AdapterError(str(exc)) from exc
            finally:
                os.close(fd)
        (temp / "vectors.json").write_bytes(_encode({"vectors": rows}))
        (temp / "source.json").write_bytes(_encode(source_doc))
        if dest.exists():
            dest.rmdir()
        os.replace(temp, dest)
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("source", type=Path)
    ap.add_argument("dest", type=Path)
    args = ap.parse_args()
    try:
        adapt(args.source, args.dest)
    except (AdapterError, ca.ManifestError, OSError, json.JSONDecodeError) as exc:
        print("could not adapt: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
