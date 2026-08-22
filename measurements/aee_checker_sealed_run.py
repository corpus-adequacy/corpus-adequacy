#!/usr/bin/env python3
"""Phase B PREPARE + inert OCI envelope for issue #211. Stdlib only.

Online materialization (pins, image, cargo vendor --locked) then sealed
OCI with network none after_materialization. subject binary is not
produced here. Does not invoke the checker. Not a scientific measurement.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import bounded_run as br  # noqa: E402
import corpus_adequacy as ca  # noqa: E402
from aee_checker_sealed_common import (  # noqa: E402
    DECLARED_CEILINGS,
    HEX64,
    MEMORY_4G,
    TMPFS_BYTES,
    TMPFS_INODES,
    PrepareError,
    encode_json,
    exact_object,
    load_strict,
    verify_file_digest,
)
from aee_checker_sealed_oci import (  # noqa: E402
    INSPECT_SNAPSHOT_KEYS,
    PROBE_MECHANISMS,
    PROBE_ROW_KEYS,
    build_inert_image,
    classify_container_result,
    container_exists,
    defense_in_depth_from_inspect,
    docker_bounded,
    docker_create_argv,
    image_platform,
    parse_inspect_payload,
    record_probe_pair,
    require_container_absent,
    require_image_id,
    require_local_image,
    require_probe_evidence,
    run_inert_probe,
    validate_inspect_contract,
)

PREPARE_SCHEMA = "corpus-adequacy.aee-checker-sealed.prepare.v0"
PREPARE_PART_KEYS = (
    "ceilings", "execution", "image", "materialized", "network",
    "non_claims", "oci", "pins", "probe_evidence", "runtime", "toolchain",
)
PREPARE_KEYS = ("phase", "schema") + PREPARE_PART_KEYS
EXECUTION_PATHS = (
    "measurements/aee_checker_sealed_run.py",
    "execution/aee-checker-sealed/Containerfile",
    "execution/aee-checker-sealed/probe.sh",
)
PHASE_A_INSTRUMENT_COMMIT = "1347651c2087cbd5c2e958a758b380a9a6cfc67d"
PHASE_A_PIN_DIGESTS = {
    "control.json": "5a85c46054240a4470da7c6a82e3f13b5f1c30ea301809a2500a47a6e2f91f71",
    "manifest.json": "2f16654dd57a0b1719ec2ec5be7a833192ccae529d08c4c7695c7df4782c32c8",
    "pins.json": "e2456cbfcbbda17800318703e296e72fcaf138037178bad1fe237bc2c460c7e4",
    "sites.json": "6223a15c5db5a7c19c4633474875615ec61f3d710e092939f46b80ee986e0c4c",
}
ADAPTER_DIGEST = "130b36d50df8a286954649771c9d65f35541ecd2f7007918ce5b261ace3aa769"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_TIMING_KEYS = frozenset({"duration", "elapsed", "elapsed_seconds", "timing", "wall_ms"})
NETWORK_CUTOFF = {
    "cutoff": "after_materialization",
    "materialization": "online",
    "sealed_oci": "none",
}
OCI_CONTRACT = {
    "cap_drop": ["ALL"],
    "memory": "4g",
    "memory_swap": "4g",
    "memory_swap_pids_claim": "inspect-verified; not efficacy-tested",
    "network": "none",
    "no_new_privileges": True,
    "pids": 512,
    "read_only": True,
    "user": "65532:65532",
}
NON_CLAIMS = (
    "not a scientific measurement",
    "checker was not run",
    "subject binary is not produced here",
    "not a scored outcome",
    "not a publication row",
    "memory/swap/pids are inspect-verified; not efficacy-tested",
)
_OUTCOME_KEYS = frozenset({"outcomes", "result", "rows", "score", "vectors", "verdict"})


def verify_phase_a_frozen(pins_dir: Path, *, adapter: Path | None = None) -> dict:
    pins_dir = Path(pins_dir)
    pins_raw = None
    for name, digest in PHASE_A_PIN_DIGESTS.items():
        try:
            raw = verify_file_digest(pins_dir / name, digest)
        except PrepareError as exc:
            raise PrepareError("phase-a artifact %s" % exc) from exc
        if name == "pins.json":
            pins_raw = raw
    pins = load_strict(pins_raw)
    if pins.get("instrument", {}).get("commit") != PHASE_A_INSTRUMENT_COMMIT:
        raise PrepareError("phase-a instrument.commit drift")
    if adapter is not None:
        verify_file_digest(adapter, ADAPTER_DIGEST)
    return pins


def require_vendor_outside(subject: Path, vendor: Path) -> None:
    subject, vendor = Path(subject).resolve(), Path(vendor).resolve()
    try:
        vendor.relative_to(subject)
    except ValueError:
        return
    raise PrepareError("vendor must be outside the subject root")


def tree_sha256(root: Path) -> str:
    root = Path(root)
    files = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + filenames:
            path = Path(dirpath) / name
            if path.is_symlink():
                raise PrepareError("symlink in tree")
        for name in filenames:
            path = Path(dirpath) / name
            if not path.is_file():
                raise PrepareError("non-regular in tree")
            files.append(path.relative_to(root).as_posix())
    if not files:
        raise PrepareError("empty vendor tree")
    digest = hashlib.sha256()
    for rel in sorted(files):
        raw = (root / rel).read_bytes()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(raw)).encode("ascii"))
        digest.update(b"\0")
        digest.update(raw)
    return digest.hexdigest()


def _git_ok(args, cwd: Path, timeout: int = 60) -> str:
    proc = br._run_capped(["git", *args], Path(cwd), timeout)
    if proc.returncode != 0:
        raise PrepareError("git failed")
    return (proc.stdout or "").strip()


def fetch_commit(url: str, commit: str, dest: Path) -> Path:
    dest = Path(dest)
    if dest.exists():
        raise PrepareError("fetch dest exists")
    dest.mkdir(parents=True)
    _git_ok(["init", str(dest)], Path.cwd(), 60)
    _git_ok(["-C", str(dest), "remote", "add", "origin", url], dest, 60)
    _git_ok(["-C", str(dest), "fetch", "--depth", "1", "origin", commit], dest, 300)
    _git_ok(["-C", str(dest), "checkout", "--detach", "FETCH_HEAD"], dest, 60)
    head = _git_ok(["-C", str(dest), "rev-parse", "HEAD"], dest, 60)
    if head != commit:
        raise PrepareError("fetched commit mismatch")
    return dest


def verify_materialized(pins: dict, subject: Path, corpus: Path) -> dict:
    check = Path(subject) / pins["subject"]["path"]
    raw = verify_file_digest(check, pins["subject"]["check_rs_sha256"])
    manifest_path = Path(corpus) / "vectors" / "MANIFEST.json"
    try:
        manifest_raw = ca.read_bounded_regular_file(manifest_path)
    except ca.ManifestError as exc:
        raise PrepareError(str(exc)) from exc
    manifest = load_strict(manifest_raw)
    if manifest.get("corpusDigest") != pins["corpus"]["corpusDigest"]:
        raise PrepareError("corpus digest mismatch")
    ids = []
    for row in manifest.get("vectors") or []:
        if type(row) is dict and isinstance(row.get("id"), str):
            ids.append(row["id"])
    return {
        "corpus_digest": manifest["corpusDigest"],
        "corpus_id_set_sha256": hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest(),
        "subject_binary": False,
        "subject_check_rs_sha256": hashlib.sha256(raw).hexdigest(),
    }


def vendor_locked(subject: Path, vendor: Path) -> str:
    require_vendor_outside(subject, vendor)
    vendor = Path(vendor)
    vendor.mkdir(parents=True, exist_ok=True)
    proc = br._run_capped(
        ["cargo", "vendor", "--locked", str(vendor.resolve())],
        Path(subject),
        300,
    )
    if proc.returncode != 0:
        raise PrepareError("cargo vendor --locked failed")
    digest = tree_sha256(vendor)
    if digest == EMPTY_SHA256:
        raise PrepareError("empty vendor")
    return digest


def materialize_pinned(pins: dict, work: Path) -> dict:
    work = Path(work)
    subject, corpus, vendor = work / "subject", work / "corpus", work / "vendor"
    fetch_commit(
        "https://github.com/%s.git" % pins["subject"]["repository"],
        pins["subject"]["commit"], subject)
    fetch_commit(
        "https://github.com/%s.git" % pins["corpus"]["repository"],
        pins["corpus"]["commit"], corpus)
    verified = verify_materialized(pins, subject, corpus)
    verified["vendor_outside_subject"] = True
    verified["vendor_sha256"] = vendor_locked(subject, vendor)
    verified["subject"] = subject
    verified["corpus"] = corpus
    verified["vendor"] = vendor
    return verified


def _distinct_identities(pins: dict, execution: dict) -> None:
    if pins.get("instrument_commit") != PHASE_A_INSTRUMENT_COMMIT:
        raise PrepareError("phase-a instrument.commit drift")
    if "instrument_commit" in execution:
        raise PrepareError("execution must not carry instrument.commit")
    if execution.get("commit") == pins.get("instrument_commit"):
        raise PrepareError("execution commit conflated with instrument")


def execution_identity(root: Path) -> dict:
    root = Path(root)
    status = _git_ok(
        ["-C", str(root), "status", "--porcelain", "--untracked-files=normal",
         "--", *EXECUTION_PATHS],
        root, 10)
    if status:
        raise PrepareError("dirty execution path")
    digest = hashlib.sha256()
    for rel in EXECUTION_PATHS:
        head_blob = _git_ok(["-C", str(root), "rev-parse", "HEAD:%s" % rel], root, 10)
        disk_blob = _git_ok(["-C", str(root), "hash-object", rel], root, 10)
        if head_blob != disk_blob:
            raise PrepareError("dirty execution path")
        raw = ca.read_bounded_regular_file(root / rel)
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(raw)).encode("ascii"))
        digest.update(b"\0")
        digest.update(raw)
    commit = _git_ok(["-C", str(root), "rev-parse", "HEAD"], root, 10)
    if len(commit) != 40:
        raise PrepareError("execution commit unresolved")
    identity = {
        "commit": commit,
        "content_sha256": digest.hexdigest(),
        "paths": list(EXECUTION_PATHS),
    }
    _distinct_identities({"instrument_commit": PHASE_A_INSTRUMENT_COMMIT}, identity)
    return identity


def record_toolchain() -> dict:
    rustc = br._run_capped(["rustc", "-Vv"], Path.cwd(), 30)
    cargo = br._run_capped(["cargo", "-V"], Path.cwd(), 30)
    if rustc.returncode != 0 or cargo.returncode != 0:
        raise PrepareError("toolchain observation failed")
    return {
        "cargo_V": (cargo.stdout or "").strip(),
        "observation": "host; checker was not run",
        "rustc_Vv": rustc.stdout or "",
    }


def prepare(pins_dir: Path, dest: Path, *, root: Path, adapter: Path | None = None) -> bytes:
    dest = Path(dest)
    pins_doc = verify_phase_a_frozen(Path(pins_dir), adapter=adapter)
    if dest.exists():
        raise PrepareError("dest exists")
    image_id = build_inert_image(Path(root) / "execution" / "aee-checker-sealed")
    with tempfile.TemporaryDirectory() as tmp:
        mats = materialize_pinned(pins_doc, Path(tmp) / "materialize")
        mounts = {
            "input": mats["corpus"],
            "vendor": mats["vendor"],
            "tool": Path(tmp) / "tool",
        }
        mounts["tool"].mkdir()
        pairs = (
            ("deadline", "deadline-ok", True, "deadline", True),
            ("disk", "tmpfs-bytes-ok", True, "tmpfs-bytes", True),
            ("file-count", "tmpfs-inodes-ok", True, "tmpfs-inodes", True),
            ("network-off", "network", False, "network", True),
            ("output", "output-ok", True, "output", True),
            ("protocol-exit", "ok", True, "exit2-json", True),
        )
        evidence = []
        for mechanism, control_mode, control_sealed, refusal_mode, refusal_sealed in pairs:
            evidence.append(record_probe_pair(
                mechanism,
                run_inert_probe(
                    image_id=image_id, mode=control_mode, mounts=mounts,
                    name_prefix="aee-sealed-prep-", sealed=control_sealed),
                run_inert_probe(
                    image_id=image_id, mode=refusal_mode, mounts=mounts,
                    name_prefix="aee-sealed-prep-", sealed=refusal_sealed),
            ))
        parts = {
            "ceilings": dict(DECLARED_CEILINGS),
            "execution": execution_identity(root),
            "image": {
                "id": image_id,
                "id_scope": "host-local",
                "kind": "inert-probe",
                "platform": image_platform(image_id),
            },
            "materialized": {
                "corpus_digest": mats["corpus_digest"],
                "corpus_id_set_sha256": mats["corpus_id_set_sha256"],
                "subject_binary": False,
                "subject_check_rs_sha256": mats["subject_check_rs_sha256"],
                "vendor_outside_subject": True,
                "vendor_sha256": mats["vendor_sha256"],
            },
            "network": dict(NETWORK_CUTOFF),
            "non_claims": list(NON_CLAIMS),
            "oci": OCI_CONTRACT,
            "pins": {
                "corpus_commit": pins_doc["corpus"]["commit"],
                "corpus_digest": pins_doc["corpus"]["corpusDigest"],
                "instrument_commit": pins_doc["instrument"]["commit"],
                "phase_a": {
                    "adapters/aee_checker_sealed.py": ADAPTER_DIGEST,
                    **{"measurements/aee-checker-25b9dfa/%s" % name: digest
                       for name, digest in PHASE_A_PIN_DIGESTS.items()},
                },
                "subject_commit": pins_doc["subject"]["commit"],
            },
            "probe_evidence": evidence,
            "runtime": {
                "docker": docker_bounded(
                    ["version", "--format", "{{.Server.Version}}"]).decode("utf-8").strip(),
                "observation": "host-local; not a portable bound",
            },
            "toolchain": record_toolchain(),
        }
    return emit_prepare_v0(parts, dest)


def _refuse_timings(doc) -> None:
    stack = [doc]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if _TIMING_KEYS.intersection(item):
                raise PrepareError("prepare must not store timings")
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def emit_prepare_v0(parts: dict, dest: Path) -> bytes:
    exact_object(parts, PREPARE_PART_KEYS, "prepare")
    _distinct_identities(parts["pins"], parts["execution"])
    if parts["ceilings"] != DECLARED_CEILINGS:
        raise PrepareError("ceilings must be the declared portable limits")
    if parts["network"] != NETWORK_CUTOFF:
        raise PrepareError("network cutoff")
    materialized = parts["materialized"]
    if type(materialized) is not dict or _OUTCOME_KEYS.intersection(materialized):
        raise PrepareError("prepare must not record per-vector outcomes")
    if materialized.get("subject_binary") is not False:
        raise PrepareError("subject binary is not produced here")
    if materialized.get("vendor_sha256") == EMPTY_SHA256:
        raise PrepareError("empty vendor")
    require_probe_evidence(parts["probe_evidence"])
    exact_object(parts["oci"], OCI_CONTRACT, "oci")
    if parts["oci"].get("memory_swap_pids_claim") != "inspect-verified; not efficacy-tested":
        raise PrepareError("memory/swap/pids must remain not efficacy-tested")
    doc = {"phase": "prepare", "schema": PREPARE_SCHEMA, **parts}
    exact_object(doc, PREPARE_KEYS, "prepare.v0")
    _refuse_timings(doc)
    raw = encode_json(doc)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(raw)
    return raw


def main(argv: list[str]) -> int:
    pins_default = _ROOT / "measurements" / "aee-checker-25b9dfa"
    adapter = _ROOT / "adapters" / "aee_checker_sealed.py"
    if len(argv) >= 2 and argv[1] == "verify-phase-a":
        pins = Path(argv[2]) if len(argv) > 2 else pins_default
        verify_phase_a_frozen(pins, adapter=adapter)
        return 0
    if len(argv) >= 4 and argv[1] == "prepare":
        prepare(Path(argv[2]), Path(argv[3]), root=_ROOT, adapter=adapter)
        return 0
    sys.stderr.write(
        "usage: aee_checker_sealed_run.py verify-phase-a [pins-dir]\n"
        "       aee_checker_sealed_run.py prepare <pins-dir> <prepare.v0>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
