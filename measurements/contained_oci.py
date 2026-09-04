"""Internal, inspect-verified OCI execution envelope. Not a completeness claim."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from secrets import token_hex

import bounded_run as br
import corpus_adequacy as ca

HEX64 = frozenset("0123456789abcdef")
CONTAINED_USER = "65532:65532"
TMPFS_BYTES = 1048576
TMPFS_INODES = 128
MEMORY_4G = 4 * 1024 * 1024 * 1024
DECLARED_CEILINGS = {
    "deadline_seconds": 8,
    "disk_bytes": TMPFS_BYTES,
    "file_count": TMPFS_INODES,
    "output_bytes": br.OUTPUT_CAP_BYTES,
}
RESOURCE_PROFILE_SCHEMA = "corpus-adequacy.aee-checker-sealed.resource-profile.v1"
RESOURCE_PROFILE_KEYS = (
    "schema", "work_bytes", "tmp_bytes", "work_inodes", "tmp_inodes",
    "work_exec", "deadline_seconds", "output_bytes", "memory_bytes",
    "memory_swap_bytes", "pids",
)

_INSPECT_ABSENT = ("no such object", "no such container")
DEFAULT_MOUNT_SPEC = (
    ("input", "/input"),
    ("vendor", "/vendor"),
    ("tool", "/tool"),
)


class PrepareError(Exception):
    """Contained execution was refused before candidate code could run."""


class DockerUnavailable(PrepareError):
    """The Docker executable is unavailable, not a successful local run."""


class ContainerSetupError(PrepareError):
    """Docker returned without proving that candidate execution started."""


class ContainerCleanupError(PrepareError):
    """Container removal or the following absence proof failed."""


def preserve_cleanup_failure(primary: BaseException, action: str,
                             failure: BaseException) -> None:
    failures = tuple(getattr(primary, "cleanup_failures", ()))
    primary.cleanup_failures = failures + ((action, failure),)
    add_note = getattr(primary, "add_note", None)
    if callable(add_note):
        try:
            add_note("%s failed: %s: %s" % (
                action, type(failure).__name__, failure))
        except BaseException:
            pass


def exact_object(doc, keys, where: str) -> None:
    if type(doc) is not dict:
        raise PrepareError("%s must be an object" % where)
    want, got = set(keys), set(doc)
    if got != want:
        raise PrepareError(
            "%s exact keys missing=%s unknown=%s" % (
                where, sorted(want - got), sorted(got - want)))


def load_strict(raw: bytes):
    try:
        return ca._parse_projection_json(raw)
    except (ca.ManifestError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PrepareError(str(exc)) from exc


def _resource_profile(*, work_bytes, tmp_bytes, work_inodes, tmp_inodes,
                      work_exec, deadline_seconds, output_bytes, memory_bytes,
                      memory_swap_bytes, pids) -> dict:
    return {
        "schema": RESOURCE_PROFILE_SCHEMA,
        "work_bytes": work_bytes,
        "tmp_bytes": tmp_bytes,
        "work_inodes": work_inodes,
        "tmp_inodes": tmp_inodes,
        "work_exec": work_exec,
        "deadline_seconds": deadline_seconds,
        "output_bytes": output_bytes,
        "memory_bytes": memory_bytes,
        "memory_swap_bytes": memory_swap_bytes,
        "pids": pids,
    }


INERT_RESOURCE_PROFILE = _resource_profile(
    work_bytes=TMPFS_BYTES,
    tmp_bytes=TMPFS_BYTES,
    work_inodes=TMPFS_INODES,
    tmp_inodes=TMPFS_INODES,
    work_exec=False,
    deadline_seconds=DECLARED_CEILINGS["deadline_seconds"],
    output_bytes=DECLARED_CEILINGS["output_bytes"],
    memory_bytes=MEMORY_4G,
    memory_swap_bytes=MEMORY_4G,
    pids=512,
)
CANDIDATE_RESOURCE_PROFILE = _resource_profile(
    work_bytes=256 * 1024 * 1024,
    tmp_bytes=16 * 1024 * 1024,
    work_inodes=16384,
    tmp_inodes=2048,
    work_exec=True,
    deadline_seconds=120,
    output_bytes=DECLARED_CEILINGS["output_bytes"],
    memory_bytes=MEMORY_4G,
    memory_swap_bytes=MEMORY_4G,
    pids=512,
)


def require_resource_profile(profile) -> dict:
    exact_object(profile, RESOURCE_PROFILE_KEYS, "resource profile")
    if profile.get("schema") != RESOURCE_PROFILE_SCHEMA:
        raise PrepareError("resource profile schema")
    for key in RESOURCE_PROFILE_KEYS:
        if key in ("schema", "work_exec"):
            continue
        value = profile[key]
        if type(value) is not int or value <= 0:
            raise PrepareError("resource profile %s" % key)
    if type(profile["work_exec"]) is not bool:
        raise PrepareError("resource profile work_exec")
    if profile["output_bytes"] != br.OUTPUT_CAP_BYTES:
        raise PrepareError("resource profile output_bytes is not enforced")
    return dict(profile)


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


def docker_run_capped(args, *, cwd: Path | None = None, timeout: int):
    try:
        return br._run_capped(
            ["docker", *args], Path(cwd) if cwd else Path.cwd(), timeout)
    except FileNotFoundError as exc:
        raise DockerUnavailable("docker executable is not available") from exc


def require_docker_ready() -> str:
    try:
        proc = docker_run_capped(
            ["info", "--format", "{{.ServerVersion}}"], timeout=15)
    except subprocess.TimeoutExpired as exc:
        raise PrepareError("docker readiness timed out") from exc
    version = (proc.stdout or "").strip()
    if proc.returncode != 0 or not version:
        raise PrepareError("docker daemon is not ready")
    return version


def docker_ok(args, *, cwd: Path | None = None, timeout: int = 60):
    proc = docker_run_capped(args, cwd=cwd, timeout=timeout)
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


def _tmpfs_spec(value, *, expected_exec=False) -> dict:
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
    if type(size) is not int or type(inodes) is not int:
        raise PrepareError("tmpfs")
    has_exec = "exec" in value.split(",")
    if has_exec is not expected_exec:
        raise PrepareError("tmpfs")
    return {"nr_inodes": inodes, "size": size}


def _require_tmpfs_match(parsed: dict, *, dest: str, size: int, inodes: int) -> None:
    if parsed.get("size") != size or parsed.get("nr_inodes") != inodes:
        raise PrepareError("tmpfs")


def validate_inspect_contract(
        inspect, *, sealed: bool, mount_spec=DEFAULT_MOUNT_SPEC,
        resource_profile=None) -> dict:
    profile = require_resource_profile(
        INERT_RESOURCE_PROFILE if resource_profile is None else resource_profile)
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
    if cfg.get("User") != CONTAINED_USER:
        raise PrepareError("user")
    if (type(host.get("Memory")) is not int or
            host.get("Memory") != profile["memory_bytes"] or
            type(host.get("MemorySwap")) is not int or
            host.get("MemorySwap") != profile["memory_swap_bytes"]):
        raise PrepareError("defense-in-depth inspect mismatch")
    if type(host.get("PidsLimit")) is not int or host.get("PidsLimit") != profile["pids"]:
        raise PrepareError("defense-in-depth inspect mismatch")
    network = host.get("NetworkMode")
    if sealed and network != "none":
        raise PrepareError("network")
    if not sealed and network == "none":
        raise PrepareError("network")
    tmpfs = host.get("Tmpfs")
    if type(tmpfs) is not dict:
        raise PrepareError("tmpfs")
    parsed = {
        "/tmp": _tmpfs_spec(tmpfs.get("/tmp")),
        "/work": _tmpfs_spec(
            tmpfs.get("/work"), expected_exec=profile["work_exec"]),
    }
    _require_tmpfs_match(
        parsed["/tmp"], dest="/tmp",
        size=profile["tmp_bytes"], inodes=profile["tmp_inodes"])
    _require_tmpfs_match(
        parsed["/work"], dest="/work",
        size=profile["work_bytes"], inodes=profile["work_inodes"])
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


def image_env_names(image_id: str) -> tuple[str, ...]:
    """Observed environment names of the pinned image, values discarded.

    The allowed environment for a contained run is the image's own
    environment plus what the create argv adds, so this is an observation
    of an immutable pinned artifact rather than a declared allowlist.
    """
    inspect = parse_inspect_payload(
        docker_bounded(["image", "inspect", require_image_id(image_id)]))
    config = inspect.get("Config")
    if type(config) is not dict or "Env" not in config:
        raise PrepareError("image env")
    env = config["Env"]
    env = [] if env is None else env
    if type(env) is not list:
        raise PrepareError("image env")
    names = []
    for item in env:
        if not isinstance(item, str):
            raise PrepareError("image env")
        names.append(item.split("=", 1)[0])
    return tuple(sorted(names))


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
    proc = docker_run_capped(["inspect", name], timeout=30)
    status = classify_inspect_status(proc.returncode, proc.stdout or "", proc.stderr or "")
    if status == "absent":
        return None
    return parse_inspect_payload((proc.stdout or "").encode("utf-8"))


def container_exists(name: str) -> bool:
    return inspect_lookup(name) is not None


def require_container_absent(name: str) -> None:
    if inspect_lookup(name) is not None:
        raise PrepareError("container still present: %s" % name)


def _docker_mem(value: int) -> str:
    if value == MEMORY_4G:
        return "4g"
    return str(value)


def docker_create_argv(
        *, image_id: str, name: str, mounts: dict, command: list[str],
        sealed: bool = True, mount_spec=DEFAULT_MOUNT_SPEC,
        entrypoint: str = "/probe", resource_profile=None) -> list[str]:
    image_id = require_image_id(image_id)
    profile = require_resource_profile(
        INERT_RESOURCE_PROFILE if resource_profile is None else resource_profile)
    normalized_mount_spec = _require_mount_spec(mount_spec)
    expected_mounts = {key for key, _destination in normalized_mount_spec}
    if set(mounts) - expected_mounts:
        raise PrepareError("unexpected mount")
    tmp_tmpfs = "rw,size=%d,nr_inodes=%d,mode=1777" % (
        profile["tmp_bytes"], profile["tmp_inodes"])
    work_tmpfs = "rw,size=%d,nr_inodes=%d,mode=1777" % (
        profile["work_bytes"], profile["work_inodes"])
    if profile["work_exec"]:
        work_tmpfs += ",exec"
    argv = [
        "docker", "create",
        "--name", name,
        "--network", "none" if sealed else "bridge",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--user", CONTAINED_USER,
        "--memory", _docker_mem(profile["memory_bytes"]),
        "--memory-swap", _docker_mem(profile["memory_swap_bytes"]),
        "--pids-limit", str(profile["pids"]),
        "--tmpfs", "/tmp:%s" % tmp_tmpfs,
        "--tmpfs", "/work:%s" % work_tmpfs,
    ]
    if sealed:
        argv.extend(["--env", "CARGO_NET_OFFLINE=true"])
    for key, destination in normalized_mount_spec:
        if key not in mounts:
            raise PrepareError("mount source missing: %s" % key)
        argv.extend([
            "--mount",
            "type=bind,source=%s,destination=%s,readonly" % (
                Path(mounts[key]).resolve(), destination),
        ])
    if type(entrypoint) is not str or not entrypoint.startswith("/"):
        raise PrepareError("entrypoint")
    argv.extend([image_id, entrypoint, *command])
    return argv


def cleanup_container(transport, name: str,
                      primary: BaseException | None,
                      label: str = "candidate") -> None:
    """Remove a named container and retain any absence-proof failure."""
    remove_failure = None
    try:
        transport.remove(name)
    except BaseException as exc:
        remove_failure = exc
        if primary is not None:
            preserve_cleanup_failure(primary, "%s remove" % label, exc)
    try:
        transport.require_absent(name)
    except BaseException as exc:
        if primary is not None:
            preserve_cleanup_failure(primary, "%s absence proof" % label, exc)
        elif remove_failure is not None:
            refusal = ContainerCleanupError("%s remove failed" % label)
            preserve_cleanup_failure(refusal, "%s absence proof" % label, exc)
            raise refusal from remove_failure
        else:
            raise ContainerCleanupError(
                "%s absence proof failed" % label) from exc
    if primary is None and remove_failure is not None:
        raise ContainerCleanupError(
            "%s remove failed" % label) from remove_failure


def classify_cleanup_result(transport, name: str) -> str:
    """Remove and prove absence, reporting the outcome instead of raising.

    A failed absence proof dominates a failed remove: the container may
    still exist. Callers that do not keep a record use `cleanup_container`,
    which still refuses.
    """
    remove_failed = False
    try:
        transport.remove(name)
    except BaseException:
        remove_failed = True
    try:
        transport.require_absent(name)
    except BaseException:
        return "absence-unproved"
    return "remove-failed" if remove_failed else "removed-and-absent"


class DockerTransport:
    """Production transport for the bounded create/start/inspect/remove funnel."""

    skip_absent = False

    def create(self, argv):
        docker_bounded(argv[1:])

    def start(self, name, deadline_seconds):
        if type(deadline_seconds) is not int or deadline_seconds <= 0:
            raise PrepareError("candidate deadline")
        return docker_run_capped(
            ["start", "-a", name], timeout=deadline_seconds)

    def inspect(self, name):
        return parse_inspect_payload(docker_bounded(["inspect", name]))

    def remove(self, name):
        docker_bounded(["rm", "-f", name])

    def require_absent(self, name):
        require_container_absent(name)

    def version(self):
        return require_docker_ready()

    def image_env_names(self, image_id):
        return image_env_names(image_id)


def require_observed_start(inspect, outcome: str, process) -> None:
    """Prove Docker started the container before classifying its outcome."""
    state = inspect.get("State") if type(inspect) is dict else None
    if (type(state) is not dict or
            state.get("Error") != "" or
            type(state.get("ExitCode")) is not int):
        raise ContainerSetupError("container start state was not proved")
    status, running = state.get("Status"), state.get("Running")
    if outcome in ("timeout", "output-cap"):
        if process is not None:
            raise ContainerSetupError("container start state was not proved")
        if (status, running) not in (("running", True), ("exited", False)):
            raise ContainerSetupError("container start state was not proved")
        return
    if (outcome != "completed" or status != "exited" or
            running is not False or
            type(getattr(process, "returncode", None)) is not int or
            state["ExitCode"] != process.returncode):
        raise ContainerSetupError("container start state was not proved")


def run_contained(
        *, image_id: str, mounts: dict, command: list[str], entrypoint: str,
        mount_spec, resource_profile, sealed: bool,
        name_prefix: str, transport=None, cleanup_label: str = "candidate",
        record_cleanup: bool = False) -> dict:
    """Run one container and return its inspect-verified raw outcome.

    `record_cleanup` is for callers that keep an execution-envelope record:
    a cleanup failure after the candidate already ran becomes a recorded
    `cleanup` state instead of an exception that loses the run. Callers that
    keep no record leave it false and a cleanup failure still refuses.
    """
    image_id = require_image_id(image_id)
    profile = require_resource_profile(resource_profile)
    if transport is None:
        require_local_image(image_id)
        transport = DockerTransport()
    if getattr(transport, "skip_absent", False):
        raise PrepareError("absence proof skipped")
    name = "%s%s" % (name_prefix, token_hex(4))
    state = None
    process = None
    try:
        argv = docker_create_argv(
            image_id=image_id,
            name=name,
            mounts=mounts,
            command=command,
            sealed=sealed,
            mount_spec=mount_spec,
            entrypoint=entrypoint,
            resource_profile=profile,
        )
        transport.create(argv)
        try:
            process = transport.start(name, profile["deadline_seconds"])
            state = "completed"
        except subprocess.TimeoutExpired:
            state = "timeout"
        except br._OutputTooLarge:
            state = "output-cap"
        observed = transport.inspect(name)
        require_observed_start(observed, state, process)
        envelope = validate_inspect_contract(
            observed,
            sealed=sealed,
            mount_spec=mount_spec,
            resource_profile=profile,
        )
    except BaseException as exc:
        cleanup_container(transport, name, exc, cleanup_label)
        raise
    if record_cleanup:
        cleanup = classify_cleanup_result(transport, name)
    else:
        cleanup_container(transport, name, None, cleanup_label)
        cleanup = "removed-and-absent"
    return {
        "cleanup": cleanup,
        "container_absent_after": cleanup == "removed-and-absent",
        "contract": envelope,
        "inspect": observed,
        "name": name,
        "process": process,
        "state": state,
    }
