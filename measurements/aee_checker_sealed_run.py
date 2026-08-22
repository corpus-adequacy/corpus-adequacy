#!/usr/bin/env python3
"""Phase B PREPARE + inert OCI envelope for issue #211. Stdlib only.

Online materialization (pins, image, vendor) then sealed OCI with
network none after_materialization. subject binary is not produced here.
Does not invoke the checker. Not a scientific measurement.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from secrets import token_hex

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import bounded_run as br  # noqa: E402
import corpus_adequacy as ca  # noqa: E402

REQUEST_SCHEMA = "corpus-adequacy.aee-checker-sealed.prepare-request.v0"
PREPARE_SCHEMA = "corpus-adequacy.aee-checker-sealed.prepare.v0"
REQUEST_KEYS = ("dest", "pins_dir", "schema")
PREPARE_PART_KEYS = (
    "ceilings", "execution", "host_evidence", "image", "materialized",
    "network", "non_claims", "oci", "pins", "runtime", "toolchain",
)
PREPARE_KEYS = ("phase", "schema") + PREPARE_PART_KEYS
EXECUTION_PATHS = (
    "measurements/aee_checker_sealed_run.py",
    "execution/aee-checker-sealed/Containerfile",
    "execution/aee-checker-sealed/probe.sh",
)
REQUEST_CAP_BYTES = 64 * 1024
PHASE_A_INSTRUMENT_COMMIT = "1347651c2087cbd5c2e958a758b380a9a6cfc67d"
PHASE_A_PIN_DIGESTS = {
    "control.json": "5a85c46054240a4470da7c6a82e3f13b5f1c30ea301809a2500a47a6e2f91f71",
    "manifest.json": "2f16654dd57a0b1719ec2ec5be7a833192ccae529d08c4c7695c7df4782c32c8",
    "pins.json": "e2456cbfcbbda17800318703e296e72fcaf138037178bad1fe237bc2c460c7e4",
    "sites.json": "6223a15c5db5a7c19c4633474875615ec61f3d710e092939f46b80ee986e0c4c",
}
ADAPTER_DIGEST = "130b36d50df8a286954649771c9d65f35541ecd2f7007918ce5b261ace3aa769"
HEX64 = frozenset("0123456789abcdef")
TMPFS_BYTES = 1048576
TMPFS_INODES = 128
DECLARED_CEILINGS = {
    "deadline_seconds": 8,
    "stdout_stderr_bytes": br.OUTPUT_CAP_BYTES,
    "tmpfs_bytes": TMPFS_BYTES,
    "tmpfs_inodes": TMPFS_INODES,
}
EMPTY_HOST_EVIDENCE = {
    "kind": "host-local",
    "portability": "host-local; not a portable bound",
    "probes": {},
}
NETWORK_CUTOFF = {
    "cutoff": "after_materialization",
    "materialization": "online",
    "sealed_oci": "none",
}
OCI_CONTRACT = {
    "cap_drop": ["ALL"],
    "cpus": "4",
    "memory": "4g",
    "memory_swap": "4g",
    "network": "none",
    "no_new_privileges": True,
    "nofile": 1024,
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
    "host evidence is not a portable bound",
)
_OUTCOME_KEYS = frozenset({"outcomes", "result", "rows", "score", "vectors", "verdict"})


class PrepareError(Exception):
    """PREPARE refused before a sealed measurement could start."""


def encode_json(doc) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def exact_object(doc, keys, where: str) -> None:
    if type(doc) is not dict:
        raise PrepareError("%s must be an object" % where)
    want, got = set(keys), set(doc)
    if got != want:
        raise PrepareError(
            "%s exact keys missing=%s unknown=%s" % (where, sorted(want - got), sorted(got - want)))


def load_strict(raw: bytes):
    try:
        return ca._parse_projection_json(raw)
    except ca.ManifestError as exc:
        raise PrepareError(str(exc)) from exc


def load_prepare_request(path: Path) -> dict:
    try:
        raw = ca.read_bounded_regular_file(Path(path), cap=REQUEST_CAP_BYTES)
    except ca.ManifestError as exc:
        raise PrepareError(str(exc)) from exc
    doc = load_strict(raw)
    exact_object(doc, REQUEST_KEYS, "request")
    if doc["schema"] != REQUEST_SCHEMA:
        raise PrepareError("request schema")
    if not isinstance(doc["pins_dir"], str) or not isinstance(doc["dest"], str):
        raise PrepareError("request paths")
    return doc


def verify_file_digest(path: Path, expected: str) -> bytes:
    try:
        raw = ca.read_bounded_regular_file(Path(path))
    except ca.ManifestError as exc:
        raise PrepareError(str(exc)) from exc
    got = hashlib.sha256(raw).hexdigest()
    if got != expected:
        raise PrepareError("digest mismatch for %s" % path)
    return raw


def verify_phase_a_frozen(pins_dir: Path, *, adapter: Path | None = None) -> None:
    pins_dir = Path(pins_dir)
    for name, digest in PHASE_A_PIN_DIGESTS.items():
        try:
            verify_file_digest(pins_dir / name, digest)
        except PrepareError as exc:
            raise PrepareError("phase-a artifact %s" % exc) from exc
    pins = load_strict((pins_dir / "pins.json").read_bytes())
    commit = pins.get("instrument", {}).get("commit")
    if commit != PHASE_A_INSTRUMENT_COMMIT:
        raise PrepareError("phase-a instrument.commit drift")
    if adapter is not None:
        verify_file_digest(adapter, ADAPTER_DIGEST)


def verify_subject_bytes(path: Path, pins: dict) -> None:
    verify_file_digest(path, pins["subject"]["check_rs_sha256"])


def require_vendor_outside(subject: Path, vendor: Path) -> None:
    subject, vendor = Path(subject).resolve(), Path(vendor).resolve()
    try:
        vendor.relative_to(subject)
    except ValueError:
        return
    raise PrepareError("vendor must be outside the subject root")


def require_image_id(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise PrepareError("image id must be sha256:<64hex>")
    digest = value[7:]
    if len(digest) != 64 or any(ch not in HEX64 for ch in digest):
        raise PrepareError("image id must be sha256:<64hex>")
    return value


def classify_container_result(returncode, raw: bytes) -> dict:
    if type(returncode) is not int:
        return {"state": "harness_failure", "parsed": None}
    if returncode == 0:
        return {"state": "completed", "parsed": None}
    return {"state": "abnormal", "parsed": None}


def docker_create_argv(*, image_id: str, name: str, mounts: dict, command: list[str]) -> list[str]:
    image_id = require_image_id(image_id)
    tmpfs = "rw,size=%d,nr_inodes=%d,mode=1777" % (TMPFS_BYTES, TMPFS_INODES)
    argv = [
        "docker", "create",
        "--name", name,
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--user", "65532:65532",
        "--memory", "4g",
        "--memory-swap", "4g",
        "--pids-limit", "512",
        "--cpus", "4",
        "--ulimit", "nofile=1024:1024",
        "--tmpfs", "/tmp:%s" % tmpfs,
        "--tmpfs", "/work:%s" % tmpfs,
        "--env", "CARGO_NET_OFFLINE=true",
    ]
    for dest in ("input", "vendor", "tool"):
        argv.extend([
            "--mount",
            "type=bind,source=%s,destination=/%s,readonly" % (Path(mounts[dest]).resolve(), dest),
        ])
    argv.extend([image_id, "/probe", *command])
    return argv


def _docker(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, timeout=timeout)


def require_local_image(image_id: str) -> None:
    image_id = require_image_id(image_id)
    proc = _docker("image", "inspect", image_id)
    if proc.returncode != 0:
        raise PrepareError("image digest mismatch")


def container_exists(name: str) -> bool:
    return _docker("inspect", name).returncode == 0


def require_container_absent(name: str, exists: bool | None = None) -> None:
    present = container_exists(name) if exists is None else bool(exists)
    if present:
        raise PrepareError("container still present: %s" % name)


def cleanup_named_containers(prefix: str) -> None:
    proc = _docker("ps", "-aq", "--filter", "name=%s" % prefix)
    for line in proc.stdout.decode("utf-8", "replace").split():
        if line:
            _docker("rm", "-f", line)


def build_inert_image(context: Path) -> str:
    proc = subprocess.run(
        ["docker", "build", "-q", "-f", "Containerfile", "."],
        cwd=str(context), capture_output=True, timeout=300)
    if proc.returncode != 0:
        raise PrepareError("inert image build failed")
    return require_image_id(proc.stdout.decode("utf-8").strip())


def run_inert_probe(*, image_id: str, mode: str, mounts: dict, name_prefix: str) -> dict:
    require_local_image(image_id)
    name = "%s%s-%s" % (name_prefix, mode.replace("-", ""), token_hex(4))
    created = False
    inspect = None
    state = "abnormal"
    try:
        created_proc = subprocess.run(
            docker_create_argv(image_id=image_id, name=name, mounts=mounts, command=[mode]),
            capture_output=True, timeout=60)
        if created_proc.returncode != 0:
            raise PrepareError("image digest mismatch")
        created = True
        try:
            proc = br._run_capped(
                ["docker", "start", "-a", name],
                Path.cwd(),
                DECLARED_CEILINGS["deadline_seconds"],
            )
            state = classify_container_result(proc.returncode, b"")["state"]
        except br._OutputTooLarge:
            state = "output_cap"
        except subprocess.TimeoutExpired:
            state = "deadline"
        inspect = json.loads(_docker("inspect", name).stdout.decode("utf-8") or "null")
    finally:
        if created:
            _docker("rm", "-f", name)
    require_container_absent(name)
    return {
        "state": state,
        "name": name,
        "inspect": inspect,
        "container_absent_after": True,
        "parsed": None,
    }


def _distinct_identities(pins: dict, execution: dict) -> None:
    if pins.get("instrument_commit") != PHASE_A_INSTRUMENT_COMMIT:
        raise PrepareError("phase-a instrument.commit drift")
    if "instrument_commit" in execution:
        raise PrepareError("execution must not carry instrument.commit")
    if execution.get("commit") == pins.get("instrument_commit"):
        raise PrepareError("execution commit conflated with instrument")


def execution_identity(root: Path) -> dict:
    root = Path(root)
    digest = hashlib.sha256()
    for rel in EXECUTION_PATHS:
        raw = (root / rel).read_bytes()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(raw)).encode("ascii"))
        digest.update(b"\0")
        digest.update(raw)
    proc = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=10)
    commit = (proc.stdout or "").strip()
    if proc.returncode != 0 or len(commit) != 40:
        raise PrepareError("execution commit unresolved")
    identity = {
        "commit": commit,
        "content_sha256": digest.hexdigest(),
        "paths": list(EXECUTION_PATHS),
    }
    _distinct_identities(
        {"instrument_commit": PHASE_A_INSTRUMENT_COMMIT}, identity)
    return identity


def record_toolchain() -> dict:
    rustc = subprocess.run(["rustc", "-Vv"], capture_output=True, text=True, timeout=30)
    cargo = subprocess.run(["cargo", "-V"], capture_output=True, text=True, timeout=30)
    if rustc.returncode != 0 or cargo.returncode != 0:
        raise PrepareError("toolchain observation failed")
    return {
        "cargo_V": cargo.stdout.strip(),
        "observation": "host; checker was not run",
        "rustc_Vv": rustc.stdout,
    }


def prepare(pins_dir: Path, dest: Path, *, root: Path, adapter: Path | None = None) -> bytes:
    pins_dir = Path(pins_dir)
    dest = Path(dest)
    verify_phase_a_frozen(pins_dir, adapter=adapter)
    if dest.exists():
        raise PrepareError("dest exists")
    pins_doc = load_strict((pins_dir / "pins.json").read_bytes())
    image_id = build_inert_image(root / "execution" / "aee-checker-sealed")
    with tempfile.TemporaryDirectory() as tmp:
        mounts = {name: Path(tmp) / name for name in ("input", "vendor", "tool")}
        for path in mounts.values():
            path.mkdir()
        require_vendor_outside(Path(tmp) / "subject", mounts["vendor"])
        ok = run_inert_probe(
            image_id=image_id, mode="ok", mounts=mounts,
            name_prefix="aee-sealed-prep-")
        if ok["state"] != "completed":
            raise PrepareError("inert ok control failed")
    parts = {
        "ceilings": dict(DECLARED_CEILINGS),
        "execution": execution_identity(root),
        "host_evidence": dict(EMPTY_HOST_EVIDENCE),
        "image": {"id": image_id, "kind": "inert-probe"},
        "materialized": {
            "corpus_digest": pins_doc["corpus"]["corpusDigest"],
            "subject_binary": False,
            "subject_check_rs_sha256": pins_doc["subject"]["check_rs_sha256"],
            "vendor_outside_subject": True,
            "vendor_sha256": hashlib.sha256(b"").hexdigest(),
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
        "runtime": {
            "docker": (_docker("version", "--format", "{{.Server.Version}}").stdout.decode("utf-8").strip()),
            "observation": "host-local; not a portable bound",
        },
        "toolchain": record_toolchain(),
    }
    return emit_prepare_v0(parts, dest)


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
    if parts["host_evidence"].get("portability") != EMPTY_HOST_EVIDENCE["portability"]:
        raise PrepareError("host evidence is not a portable bound")
    doc = {"phase": "prepare", "schema": PREPARE_SCHEMA, **parts}
    exact_object(doc, PREPARE_KEYS, "prepare.v0")
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
