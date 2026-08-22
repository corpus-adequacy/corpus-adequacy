#!/usr/bin/env python3
"""Phase B PREPARE + inert OCI envelope for issue #211. Stdlib only.

Online materialization (pinned archives, cargo vendor --locked) then sealed
OCI with network none after_materialization. subject binary is not
produced here. Does not invoke the checker. Not a scientific measurement.
"""

from __future__ import annotations

import hashlib
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
    EMPTY_SHA256,
    FROZEN_CORPUS_MANIFEST_SHA256,
    FROZEN_CORPUS_TREE_SHA256,
    FROZEN_SUBJECT_TREE_SHA256,
    MATERIALIZE_CEILINGS,
    MaterializeBudget,
    HEX64,
    MEMORY_4G,
    TMPFS_BYTES,
    TMPFS_INODES,
    DockerUnavailable,
    PrepareError,
    encode_json,
    exact_object,
    load_strict,
    verify_file_digest,
)
from aee_checker_sealed_materialize import (  # noqa: E402
    CORPUS_ID_COUNT,
    MATERIALIZE_CAP_BYTES,
    MATERIALIZE_CAP_FILES,
    RUST_IMAGE,
    abort_atomic_dest,
    archive_member_rel,
    begin_atomic_dest,
    bind_vendor_config,
    charge_existing_tree,
    commit_atomic_dest,
    download_bounded,
    extract_pinned_archive,
    materialize_pinned,
    pull_rust_image,
    copy_tmpfs_argv,
    copy_tmpfs_as_bind_owner,
    host_bind_owner,
    refuse_archive_link,
    refuse_duplicate_member,
    require_corpus_id_set,
    require_frozen_manifest_sha,
    require_frozen_trees,
    require_vendor_outside,
    require_vendor_toolchain,
    stream_archive_member,
    tree_sha256,
    vendor_create_argv,
    vendor_locked,
    verify_materialized,
)
from aee_checker_sealed_oci import (  # noqa: E402
    DEFAULT_MOUNT_SPEC,
    EXPECTED_REFUSALS,
    INSPECT_SNAPSHOT_KEYS,
    PROBE_MECHANISMS,
    PROBE_ROW_KEYS,
    build_inert_image,
    classify_container_result,
    classify_inspect_status,
    container_exists,
    defense_in_depth_from_inspect,
    docker_bounded,
    docker_create_argv,
    docker_ok,
    image_platform,
    inspect_lookup,
    parse_inspect_payload,
    record_probe_pair,
    require_container_absent,
    require_docker_ready,
    require_image_id,
    require_live_oci_capability,
    require_local_image,
    require_probe_evidence,
    run_inert_probe,
    validate_inspect_contract,
)

PREPARE_SCHEMA = "corpus-adequacy.aee-checker-sealed.prepare.v0"
PREPARE_PART_KEYS = (
    "ceilings", "execution", "image", "materialize_ceilings", "materialized",
    "network", "non_claims", "oci", "pins", "probe_evidence", "runtime",
    "toolchain",
)
SEALED_PROBE_PAIRS = {
    "deadline": ("deadline-ok", "deadline"),
    "disk": ("tmpfs-bytes-ok", "tmpfs-bytes"),
    "file-count": ("tmpfs-inodes-ok", "tmpfs-inodes"),
    "output": ("output-ok", "output"),
    "protocol-exit": ("ok", "exit2-json"),
}
PREPARE_KEYS = ("phase", "schema") + PREPARE_PART_KEYS
EXECUTION_PATHS = (
    "measurements/aee_checker_sealed_run.py",
    "measurements/aee_checker_sealed_common.py",
    "measurements/aee_checker_sealed_oci.py",
    "measurements/aee_checker_sealed_candidate.py",
    "measurements/aee_checker_sealed_materialize.py",
    "measurements/aee_checker_sealed_authorize.py",
    "measurements/aee_checker_sealed_execute.py",
    "execution/aee-checker-sealed/Containerfile",
    "execution/aee-checker-sealed/probe.sh",
    "execution/aee-checker-sealed/cargo-config.toml",
)
MATERIALIZED_KEYS = (
    "corpus_digest", "corpus_id_count", "corpus_id_set_sha256",
    "corpus_manifest_sha256", "corpus_tree_sha256", "subject_binary",
    "subject_check_rs_sha256", "subject_tree_sha256", "tool_config_sha256",
    "vendor_outside_subject", "vendor_sha256",
)
PHASE_A_INSTRUMENT_COMMIT = "1347651c2087cbd5c2e958a758b380a9a6cfc67d"
PHASE_A_PIN_DIGESTS = {
    "control.json": "5a85c46054240a4470da7c6a82e3f13b5f1c30ea301809a2500a47a6e2f91f71",
    "manifest.json": "2f16654dd57a0b1719ec2ec5be7a833192ccae529d08c4c7695c7df4782c32c8",
    "pins.json": "e2456cbfcbbda17800318703e296e72fcaf138037178bad1fe237bc2c460c7e4",
    "sites.json": "6223a15c5db5a7c19c4633474875615ec61f3d710e092939f46b80ee986e0c4c",
}
ADAPTER_DIGEST = "130b36d50df8a286954649771c9d65f35541ecd2f7007918ce5b261ace3aa769"
_TIMING_KEYS = frozenset({
    "built_at", "created", "created_at", "ctime", "duration", "elapsed",
    "elapsed_seconds", "host_path", "mtime", "timestamp", "timing", "wall_ms",
})
_HOST_MARKERS = (
    "/Users/", "/home/", "/private/tmp/", "/private/var/", "/var/folders/",
    "C:/", "C:\\",
)
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


def _git_ok(args, cwd: Path, timeout: int = 60) -> str:
    proc = br._run_capped(["git", *args], Path(cwd), timeout)
    if proc.returncode != 0:
        raise PrepareError("git failed")
    return (proc.stdout or "").strip()


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


def record_toolchain(toolchain: dict) -> dict:
    return require_vendor_toolchain(toolchain)


def resolve_prepare_image(image_id, *, root: Path) -> str:
    """Reuse a local sha256 image, or build the inert image once."""
    if image_id is None:
        return build_inert_image(Path(root) / "execution" / "aee-checker-sealed")
    require_local_image(image_id)
    return require_image_id(image_id)


def prepare(pins_dir: Path, dest: Path, *, root: Path, adapter: Path | None = None,
            image_id=None) -> bytes:
    dest = Path(dest)
    pins_doc = verify_phase_a_frozen(Path(pins_dir), adapter=adapter)
    require_docker_ready()
    image_id = resolve_prepare_image(image_id, root=root)
    template = Path(root) / "execution" / "aee-checker-sealed" / "cargo-config.toml"
    with tempfile.TemporaryDirectory() as scratch:
        pre_mounts = {name: Path(scratch) / name for name in ("input", "vendor", "tool")}
        for path in pre_mounts.values():
            path.mkdir()
        network_control = run_inert_probe(
            image_id=image_id, mode="network", mounts=pre_mounts,
            name_prefix="aee-sealed-prep-", sealed=False)
    state = begin_atomic_dest(dest)
    try:
        mats = materialize_pinned(pins_doc, state["staging"], template=template)
        mounts = {
            "input": mats["corpus"],
            "vendor": mats["vendor"],
            "tool": mats["tool"],
        }
        evidence = []
        for mechanism in PROBE_MECHANISMS:
            if mechanism == "network-off":
                evidence.append(record_probe_pair(
                    mechanism,
                    network_control,
                    run_inert_probe(
                        image_id=image_id, mode="network", mounts=mounts,
                        name_prefix="aee-sealed-prep-", sealed=True),
                ))
                continue
            control_mode, refusal_mode = SEALED_PROBE_PAIRS[mechanism]
            evidence.append(record_probe_pair(
                mechanism,
                run_inert_probe(
                    image_id=image_id, mode=control_mode, mounts=mounts,
                    name_prefix="aee-sealed-prep-", sealed=True),
                run_inert_probe(
                    image_id=image_id, mode=refusal_mode, mounts=mounts,
                    name_prefix="aee-sealed-prep-", sealed=True),
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
            "materialize_ceilings": dict(MATERIALIZE_CEILINGS),
            "materialized": {key: mats[key] for key in MATERIALIZED_KEYS},
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
            "toolchain": record_toolchain(mats["toolchain"]),
        }
        raw = emit_prepare_v0(parts, state["staging"] / "prepare.v0.json")
        commit_atomic_dest(state)
    except Exception:
        abort_atomic_dest(state)
        raise
    return raw


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
        elif isinstance(item, str):
            if any(marker in item for marker in _HOST_MARKERS):
                raise PrepareError("prepare must not store host paths")


def emit_prepare_v0(parts: dict, dest: Path) -> bytes:
    exact_object(parts, PREPARE_PART_KEYS, "prepare")
    _distinct_identities(parts["pins"], parts["execution"])
    if parts["ceilings"] != DECLARED_CEILINGS:
        raise PrepareError("ceilings must be the declared portable limits")
    if parts["materialize_ceilings"] != MATERIALIZE_CEILINGS:
        raise PrepareError("materialize ceilings must be the declared portable limits")
    if parts["network"] != NETWORK_CUTOFF:
        raise PrepareError("network cutoff")
    materialized = parts["materialized"]
    exact_object(materialized, MATERIALIZED_KEYS, "materialized")
    require_frozen_trees(
        materialized.get("subject_tree_sha256"),
        materialized.get("corpus_tree_sha256"),
    )
    if _OUTCOME_KEYS.intersection(materialized):
        raise PrepareError("prepare must not record per-vector outcomes")
    if materialized.get("subject_binary") is not False:
        raise PrepareError("subject binary is not produced here")
    if materialized.get("vendor_sha256") == EMPTY_SHA256:
        raise PrepareError("empty vendor")
    if materialized.get("corpus_id_count") != CORPUS_ID_COUNT:
        raise PrepareError("corpus must list exactly %d unique ids" % CORPUS_ID_COUNT)
    if materialized.get("corpus_manifest_sha256") != FROZEN_CORPUS_MANIFEST_SHA256:
        raise PrepareError("corpus manifest sha mismatch")
    require_probe_evidence(parts["probe_evidence"])
    require_vendor_toolchain(parts["toolchain"])
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
    if len(argv) in (4, 5) and argv[1] == "prepare":
        image_id = argv[4] if len(argv) == 5 else None
        prepare(Path(argv[2]), Path(argv[3]), root=_ROOT, adapter=adapter,
                image_id=image_id)
        return 0
    sys.stderr.write(
        "usage: aee_checker_sealed_run.py verify-phase-a [pins-dir]\n"
        "       aee_checker_sealed_run.py prepare <pins-dir> <out-dir> [image-id]\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
