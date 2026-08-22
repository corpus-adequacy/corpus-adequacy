"""Bounded Docker create/inspect for the inert #211 probe. Not a checker."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from secrets import token_hex

import bounded_run as br

from aee_checker_sealed_common import (
    DECLARED_CEILINGS,
    HEX64,
    MEMORY_4G,
    TMPFS_BYTES,
    TMPFS_INODES,
    DockerUnavailable,
    PrepareError,
    exact_object,
    load_strict,
)

INSPECT_SNAPSHOT_KEYS = (
    "cap_drop", "memory", "memory_swap", "network_mode",
    "no_new_privileges", "offline_env", "pids", "read_only_root",
    "readonly_mounts", "tmpfs", "user",
)
PROBE_MECHANISMS = (
    "deadline", "disk", "file-count", "network-off", "output", "protocol-exit",
)
EXPECTED_REFUSALS = {
    "deadline": "deadline",
    "disk": "abnormal",
    "file-count": "abnormal",
    "network-off": "abnormal",
    "output": "output_cap",
    "protocol-exit": "abnormal",
}
PROBE_ROW_KEYS = ("control", "inspect", "mechanism", "refusal")
_INSPECT_ABSENT = ("no such object", "no such container")
DEFAULT_MOUNT_SPEC = (
    ("input", "/input"),
    ("vendor", "/vendor"),
    ("tool", "/tool"),
)


def _require_mount_spec(mount_spec) -> tuple[tuple[str, str], ...]:
    if type(mount_spec) not in (list, tuple) or not mount_spec:
        raise PrepareError("mount specification")
    normalized = []
    keys = set()
    destinations = set()
    for item in mount_spec:
        if type(item) not in (list, tuple) or len(item) != 2:
            raise PrepareError("mount specification")
        key, destination = item
        if (not isinstance(key, str) or not key or
                not isinstance(destination, str) or not destination.startswith("/")):
            raise PrepareError("mount specification")
        if key in keys or destination in destinations:
            raise PrepareError("mount specification")
        keys.add(key)
        destinations.add(destination)
        normalized.append((key, destination))
    return tuple(normalized)


def require_docker_ready() -> str:
    try:
        proc = br._run_capped(
            ["docker", "info", "--format", "{{.ServerVersion}}"], Path.cwd(), 15)
    except FileNotFoundError as exc:
        raise DockerUnavailable("docker executable is not available") from exc
    version = (proc.stdout or "").strip()
    if proc.returncode != 0 or not version:
        raise PrepareError("docker daemon is not ready")
    return version


def require_live_oci_capability(context: Path) -> str:
    require_docker_ready()
    return build_inert_image(Path(context))


def docker_ok(args, *, cwd: Path | None = None, timeout: int = 60):
    proc = br._run_capped(["docker", *args], Path(cwd) if cwd else Path.cwd(), timeout)
    if proc.returncode != 0:
        raise PrepareError("docker %s failed" % (args[0] if args else "cmd"))
    return proc


def docker_bounded(args, *, cwd: Path | None = None, timeout: int = 60) -> bytes:
    text = docker_ok(args, cwd=cwd, timeout=timeout).stdout or ""
    if not str(text).strip():
        raise PrepareError("docker output empty")
    return text.encode("utf-8")


def parse_inspect_payload(raw: bytes) -> dict:
    if not raw or not raw.strip():
        raise PrepareError("inspect empty")
    doc = load_strict(raw)
    if type(doc) is not list or len(doc) != 1 or type(doc[0]) is not dict:
        raise PrepareError("inspect shape")
    return doc[0]


def _tmpfs_spec(value) -> dict:
    if not isinstance(value, str):
        raise PrepareError("tmpfs")
    size = inodes = None
    try:
        for part in value.split(","):
            if part.startswith("size="):
                size = int(part[5:])
            elif part.startswith("nr_inodes="):
                inodes = int(part[10:])
    except ValueError as exc:
        raise PrepareError("tmpfs") from exc
    if size != TMPFS_BYTES or inodes != TMPFS_INODES:
        raise PrepareError("tmpfs")
    return {"nr_inodes": inodes, "size": size}


def validate_inspect_contract(
        inspect, *, sealed: bool, mount_spec=DEFAULT_MOUNT_SPEC) -> dict:
    if type(inspect) is not dict:
        raise PrepareError("inspect missing")
    host, cfg = inspect.get("HostConfig"), inspect.get("Config")
    if type(host) is not dict or type(cfg) is not dict:
        raise PrepareError("inspect missing HostConfig")
    if host.get("ReadonlyRootfs") is not True:
        raise PrepareError("read-only root")
    if host.get("CapDrop") != ["ALL"]:
        raise PrepareError("cap-drop")
    sec = host.get("SecurityOpt") or []
    no_new_privileges = any(
        str(item).replace("=", ":") == "no-new-privileges:true" for item in sec)
    if not no_new_privileges:
        raise PrepareError("no-new-privileges")
    if cfg.get("User") != "65532:65532":
        raise PrepareError("user")
    if (type(host.get("Memory")) is not int or host.get("Memory") != MEMORY_4G or
            type(host.get("MemorySwap")) is not int or
            host.get("MemorySwap") != MEMORY_4G):
        raise PrepareError("defense-in-depth inspect mismatch")
    if type(host.get("PidsLimit")) is not int or host.get("PidsLimit") != 512:
        raise PrepareError("defense-in-depth inspect mismatch")
    network = host.get("NetworkMode")
    if sealed and network != "none":
        raise PrepareError("network")
    if not sealed and network == "none":
        raise PrepareError("network")
    tmpfs = host.get("Tmpfs")
    if type(tmpfs) is not dict:
        raise PrepareError("tmpfs")
    parsed = {dest: _tmpfs_spec(tmpfs.get(dest)) for dest in ("/tmp", "/work")}
    mounts = inspect.get("Mounts")
    if type(mounts) is not list:
        raise PrepareError("readonly mount")
    required_destinations = {
        destination for _, destination in _require_mount_spec(mount_spec)
    }
    found = set()
    for mount in mounts:
        if type(mount) is not dict:
            raise PrepareError("readonly mount")
        dest = mount.get("Destination")
        if (dest not in required_destinations or dest in found or
                mount.get("Type") != "bind" or mount.get("RW") is not False):
            raise PrepareError("readonly mount")
        found.add(dest)
    if found != required_destinations:
        raise PrepareError("readonly mount")
    env = cfg.get("Env") or []
    offline = any(item == "CARGO_NET_OFFLINE=true" for item in env)
    if sealed != offline:
        raise PrepareError("offline env")
    return {
        "cap_drop": list(host["CapDrop"]),
        "memory": host["Memory"],
        "memory_swap": host["MemorySwap"],
        "network_mode": network,
        "no_new_privileges": no_new_privileges,
        "offline_env": offline,
        "pids": host["PidsLimit"],
        "read_only_root": host["ReadonlyRootfs"],
        "readonly_mounts": sorted(found),
        "tmpfs": parsed,
        "user": cfg["User"],
    }


def require_image_id(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise PrepareError("image id must be sha256:<64hex>")
    digest = value[7:]
    if len(digest) != 64 or any(ch not in HEX64 for ch in digest):
        raise PrepareError("image id must be sha256:<64hex>")
    return value


def require_local_image(image_id: str) -> None:
    docker_bounded(["image", "inspect", require_image_id(image_id)])


def image_platform(image_id: str) -> str:
    inspect = parse_inspect_payload(docker_bounded(["image", "inspect", image_id]))
    os_name, arch = inspect.get("Os"), inspect.get("Architecture")
    if not os_name or not arch:
        raise PrepareError("image platform")
    return "%s/%s" % (os_name, arch)


def classify_inspect_status(returncode, stdout, stderr) -> str:
    if type(returncode) is not int:
        raise PrepareError("inspect infrastructure")
    if returncode == 0:
        if not str(stdout or "").strip():
            raise PrepareError("inspect empty")
        return "present"
    text = "%s\n%s" % (stderr or "", stdout or "")
    lowered = text.lower()
    if any(token in lowered for token in _INSPECT_ABSENT):
        return "absent"
    raise PrepareError("inspect infrastructure")


def inspect_lookup(name: str):
    proc = br._run_capped(["docker", "inspect", name], Path.cwd(), 30)
    status = classify_inspect_status(proc.returncode, proc.stdout or "", proc.stderr or "")
    if status == "absent":
        return None
    return parse_inspect_payload((proc.stdout or "").encode("utf-8"))


def container_exists(name: str) -> bool:
    return inspect_lookup(name) is not None


def require_container_absent(name: str) -> None:
    if inspect_lookup(name) is not None:
        raise PrepareError("container still present: %s" % name)


def docker_create_argv(
        *, image_id: str, name: str, mounts: dict, command: list[str],
        sealed: bool = True, mount_spec=DEFAULT_MOUNT_SPEC) -> list[str]:
    image_id = require_image_id(image_id)
    tmpfs = "rw,size=%d,nr_inodes=%d,mode=1777" % (TMPFS_BYTES, TMPFS_INODES)
    argv = [
        "docker", "create",
        "--name", name,
        "--network", "none" if sealed else "bridge",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--user", "65532:65532",
        "--memory", "4g",
        "--memory-swap", "4g",
        "--pids-limit", "512",
        "--tmpfs", "/tmp:%s" % tmpfs,
        "--tmpfs", "/work:%s" % tmpfs,
    ]
    if sealed:
        argv.extend(["--env", "CARGO_NET_OFFLINE=true"])
    for key, destination in _require_mount_spec(mount_spec):
        if key not in mounts:
            raise PrepareError("mount source missing: %s" % key)
        argv.extend([
            "--mount",
            "type=bind,source=%s,destination=%s,readonly" % (
                Path(mounts[key]).resolve(), destination),
        ])
    argv.extend([image_id, "/probe", *command])
    return argv


def build_inert_image(context: Path) -> str:
    os.environ.setdefault("DOCKER_BUILDKIT", "1")
    raw = docker_bounded(
        ["build", "-q", "-f", "Containerfile", "."],
        cwd=Path(context), timeout=300)
    return require_image_id(raw.decode("utf-8").strip())


def classify_container_result(returncode, raw: bytes) -> dict:
    if type(returncode) is not int:
        return {"state": "harness_failure", "parsed": None}
    if returncode == 0:
        return {"state": "completed", "parsed": None}
    return {"state": "abnormal", "parsed": None}


def record_probe_pair(mechanism: str, control: dict, refusal: dict) -> dict:
    expected = EXPECTED_REFUSALS.get(mechanism)
    if expected is None:
        raise PrepareError("unknown probe mechanism")
    if control.get("state") != "completed":
        raise PrepareError("probe pair missing control")
    if refusal.get("state") != expected:
        raise PrepareError("probe refusal must be %s" % expected)
    if type(control.get("contract")) is not dict or type(refusal.get("contract")) is not dict:
        raise PrepareError("probe pair missing inspect")
    return {
        "control": "completed",
        "inspect": {"control": control["contract"], "refusal": refusal["contract"]},
        "mechanism": mechanism,
        "refusal": expected,
    }


def require_probe_evidence(rows) -> None:
    if type(rows) is not list or len(rows) != len(PROBE_MECHANISMS):
        raise PrepareError("probe evidence must pair every required mechanism")
    for expected, row in zip(PROBE_MECHANISMS, rows):
        exact_object(row, PROBE_ROW_KEYS, "probe evidence")
        if row["mechanism"] != expected or row["control"] != "completed":
            raise PrepareError("probe pair missing control")
        want = EXPECTED_REFUSALS[expected]
        if row["refusal"] != want:
            raise PrepareError("%s refusal must be %s" % (expected, want))
        exact_object(row["inspect"], ("control", "refusal"), "probe inspect")
        for side in row["inspect"].values():
            exact_object(side, INSPECT_SNAPSHOT_KEYS, "inspect snapshot")


def defense_in_depth_from_inspect(inspect) -> dict:
    row = inspect[0] if isinstance(inspect, list) and inspect else inspect
    snap = validate_inspect_contract(row, sealed=True)
    return {
        "claim": "inspect-verified; not efficacy-tested",
        "memory": snap["memory"],
        "memory_swap": snap["memory_swap"],
        "pids": snap["pids"],
    }


def run_inert_probe(
        *, image_id: str, mode: str, mounts: dict, name_prefix: str,
        sealed: bool = True, mount_spec=DEFAULT_MOUNT_SPEC) -> dict:
    require_local_image(image_id)
    name = "%s%s-%s" % (name_prefix, mode.replace("-", ""), token_hex(4))
    created = False
    inspect = None
    contract = None
    state = "abnormal"
    error = None
    try:
        docker_bounded(docker_create_argv(
            image_id=image_id, name=name, mounts=mounts, command=[mode],
            sealed=sealed, mount_spec=mount_spec)[1:])
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
        inspect = parse_inspect_payload(docker_bounded(["inspect", name]))
        contract = validate_inspect_contract(
            inspect, sealed=sealed, mount_spec=mount_spec)
    except PrepareError as exc:
        error = exc
    finally:
        if created:
            try:
                docker_bounded(["rm", "-f", name])
            except PrepareError as exc:
                require_container_absent(name)
                raise PrepareError("container remove failed") from exc
    require_container_absent(name)
    if error is not None:
        raise error
    if contract is None:
        raise PrepareError("inspect empty")
    return {
        "state": state,
        "name": name,
        "inspect": inspect,
        "contract": contract,
        "container_absent_after": True,
        "parsed": None,
    }
