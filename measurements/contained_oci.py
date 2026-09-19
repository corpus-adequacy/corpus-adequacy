"""Internal, inspect-verified OCI execution envelope. Not a completeness claim."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from secrets import token_hex

import contained_contract as _contract
import bounded_run as br
import corpus_adequacy as ca

HEX64 = _contract.HEX64
CONTAINED_USER = _contract.CONTAINED_USER
TMPFS_BYTES = _contract.TMPFS_BYTES
TMPFS_INODES = _contract.TMPFS_INODES
MEMORY_4G = _contract.MEMORY_4G
DECLARED_CEILINGS = _contract.DECLARED_CEILINGS
RESOURCE_PROFILE_SCHEMA = _contract.RESOURCE_PROFILE_SCHEMA
RESOURCE_PROFILE_V2_SCHEMA = _contract.RESOURCE_PROFILE_V2_SCHEMA
# One CPU expressed in thousandths, so the Docker rate argument is exact integer arithmetic and
# no float ever reaches the wire. Operator policy, not measured tuning.
CPU_PERIOD_USEC = _contract.CPU_PERIOD_USEC
MILLICPU_PER_CPU = _contract.MILLICPU_PER_CPU
# A representational ceiling, NOT a tuned CPU policy and not an applied host limit. The emitted
# quota is written into a cgroup interface that reads a signed 64-bit microsecond value, so a rate
# whose quota cannot be represented there is refused here rather than encoded and rejected later
# by something that never sees this codec. Positive-and-integer was not bounded: 10**100 passed.
_INT64_MAX = _contract._INT64_MAX
MAX_CPU_RATE_MILLICPU = _contract.MAX_CPU_RATE_MILLICPU
# Descriptor limits are per-process RLIMIT values passed as decimal on the wire; bound them by the
# same representational argument rather than leaving an unbounded integer.
MAX_NOFILE = _contract.MAX_NOFILE
RESOURCE_PROFILE_KEYS = _contract.RESOURCE_PROFILE_KEYS
# v2 is a sibling: v1's keys and its fixture are untouched, and neither loader admits the other.
RESOURCE_PROFILE_V2_KEYS = _contract.RESOURCE_PROFILE_V2_KEYS

_INSPECT_ABSENT = ("no such object", "no such container")
DEFAULT_MOUNT_SPEC = _contract.DEFAULT_MOUNT_SPEC


class PrepareError(Exception):
    """Contained execution was refused before candidate code could run."""


def _contract_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except _contract.ContractError as exc:
        raise PrepareError(str(exc)) from exc


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
    return _contract_call(_contract.exact_object, doc, keys, where)


def load_strict(raw: bytes):
    try:
        return ca._parse_projection_json(raw)
    except (ca.ManifestError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PrepareError(str(exc)) from exc


def _resource_profile(*, work_bytes, tmp_bytes, work_inodes, tmp_inodes, work_exec, deadline_seconds, output_bytes, memory_bytes, memory_swap_bytes, pids) -> dict:
    return _contract_call(_contract._resource_profile, work_bytes=work_bytes, tmp_bytes=tmp_bytes, work_inodes=work_inodes, tmp_inodes=tmp_inodes, work_exec=work_exec, deadline_seconds=deadline_seconds, output_bytes=output_bytes, memory_bytes=memory_bytes, memory_swap_bytes=memory_swap_bytes, pids=pids)


INERT_RESOURCE_PROFILE = _contract.INERT_RESOURCE_PROFILE
CANDIDATE_RESOURCE_PROFILE = _contract.CANDIDATE_RESOURCE_PROFILE
CANDIDATE_RESOURCE_PROFILE_V2 = _contract.CANDIDATE_RESOURCE_PROFILE_V2


def _require_positive_int(profile, key) -> int:
    """`type(...) is not int` rather than isinstance: bool is an int subclass, and a profile
    carrying True where a count belongs must refuse rather than be read as 1."""
    return _contract_call(_contract._require_positive_int, profile, key)


def _require_cpu_and_nofile(profile) -> None:
    """v2-only policy. Ints only, so no float, NaN, infinity or bool can reach the argv, and
    finite, so an unrepresentable rate refuses here instead of being encoded."""
    return _contract_call(_contract._require_cpu_and_nofile, profile)


# Closed schema selection over ONE rule. Two copied validators would drift, and the drift would
# be invisible until a profile validated differently in two places.
_PROFILE_POLICIES = _contract._PROFILE_POLICIES


def _require_profile(profile, *, schema: str) -> dict:
    return _contract_call(_contract._require_profile, profile, schema=schema)


def require_resource_profile(profile) -> dict:
    """The v1 loader, unchanged in meaning: it admits v1 and refuses v2 by exact keys."""
    return _contract_call(_contract.require_resource_profile, profile)


def require_resource_profile_v2(profile) -> dict:
    return _contract_call(_contract.require_resource_profile_v2, profile)


def require_versioned_resource_profile(profile) -> dict:
    """Admit a v1 or a v2 profile, selected by its own schema field, through the one shared rule.

    For the container funnel only, which serves both versions. Which version a run may use is
    decided upstream by the resolved execution profile; this selects the validator, not the policy.
    """
    return _contract_call(_contract.require_versioned_resource_profile, profile)


def cpu_quota_usec(profile) -> int:
    """The one mapping from a v2 rate to the CFS quota, shared by the argv and the comparator."""
    return _contract_call(_contract.cpu_quota_usec, profile)


def docker_resource_argv_v2(profile) -> list[str]:
    """The CPU rate and descriptor arguments implied by a validated v2 profile.

    Encoding an argument is not applying or observing a limit. `docker_create_argv` emits these
    for a v2 profile only, so a v1 argv never gains them. The rate is a cgroup aggregate quota
    over a period, kept in period/quota form because the CPU-count flag would store `NanoCpus`
    and leave both observed fields unset; the wall deadline remains a separate, independently
    enforced bound and does not appear here.
    """
    checked = require_resource_profile_v2(profile)
    quota = cpu_quota_usec(checked)
    return [
        "--cpu-period", str(CPU_PERIOD_USEC),
        "--cpu-quota", str(quota),
        "--ulimit", "nofile=%d:%d" % (checked["nofile_soft"], checked["nofile_hard"]),
    ]


def validate_mount_destinations(destinations, *, strictly_sorted: bool=False) -> tuple[str, ...]:
    """Validate a sequence of mount destinations.

    Destinations must be a non-empty sequence of non-empty absolute path strings,
    with no duplicates. When strictly_sorted is True, items must be strictly increasing.
    """
    return _contract_call(_contract.validate_mount_destinations, destinations, strictly_sorted=strictly_sorted)


def _require_mount_spec(mount_spec) -> tuple[tuple[str, str], ...]:
    return _contract_call(_contract._require_mount_spec, mount_spec)


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


def _required_stdout(proc) -> bytes:
    text = proc.stdout or ""
    if not str(text).strip():
        raise PrepareError("docker output empty")
    return text.encode("utf-8")


def docker_bounded(args, *, cwd: Path | None = None, timeout: int = 60) -> bytes:
    return _required_stdout(docker_ok(args, cwd=cwd, timeout=timeout))


def create_warnings_from_stderr(stderr) -> tuple:
    """Every non-empty stderr line of `docker create`, stripped, `WARNING: ` removed.

    moby (v28.0.4 daemon/daemon_unix.go `verifyPlatformContainerResources`) can discard a
    requested limit, store the changed config and say so only in the create response's
    warnings; docker/cli (v28.0.4 cli/command/container/create.go) prints each on stderr as
    `WARNING: <text>`. Every line counts, not only WARNING lines or lines naming a discard:
    moby's swap warning ends "Memory limited without swap." and never says "discarded".
    """
    warnings = []
    for line in str(stderr or "").splitlines():
        line = line.strip()
        if line.startswith("WARNING: "):
            line = line[len("WARNING: "):]
        if line:
            warnings.append(line)
    return tuple(warnings)


def parse_inspect_payload(raw: bytes) -> dict:
    if not raw or not raw.strip():
        raise PrepareError("inspect empty")
    doc = load_strict(raw)
    if type(doc) is not list or len(doc) != 1 or type(doc[0]) is not dict:
        raise PrepareError("inspect shape")
    return doc[0]


def contained_user_ids(value=None) -> tuple[int, int]:
    """Parse the one canonical Docker uid:gid declaration without normalization."""
    return _contract_call(_contract.contained_user_ids, value)


def _canonical_uint(value: str) -> int:
    return _contract_call(_contract._canonical_uint, value)


def parse_tmpfs_options(value, *, owner_bound: bool) -> dict:
    """Parse a closed Docker tmpfs declaration; v2 additionally binds its owner."""
    return _contract_call(_contract.parse_tmpfs_options, value, owner_bound=owner_bound)


def tmpfs_request(profile: dict, *, destination: str, owner_bound: bool) -> dict:
    return _contract_call(_contract.tmpfs_request, profile, destination=destination, owner_bound=owner_bound)


def require_tmpfs_spec(spec, *, owner_bound: bool) -> dict:
    """Validate the exact structured tmpfs value shared by writers and readers."""
    return _contract_call(_contract.require_tmpfs_spec, spec, owner_bound=owner_bound)


def encode_tmpfs_options(spec: dict, *, owner_bound: bool) -> str:
    require_tmpfs_spec(spec, owner_bound=owner_bound)
    if owner_bound:
        text = "rw,%s,mode=%s,uid=%d,gid=%d,size=%d,nr_inodes=%d" % (
            "exec" if spec["exec"] else "noexec", spec["mode"], spec["uid"],
            spec["gid"], spec["size"], spec["nr_inodes"])
    else:
        text = "rw,size=%d,nr_inodes=%d,mode=%s%s" % (
            spec["size"], spec["nr_inodes"], spec["mode"],
            ",exec" if spec["exec"] else "")
    if parse_tmpfs_options(text, owner_bound=owner_bound) != spec:
        raise PrepareError("tmpfs")
    return text


def _tmpfs_spec(value, *, expected_exec=False, owner_bound=False) -> dict:
    parsed = parse_tmpfs_options(value, owner_bound=owner_bound)
    if parsed["exec"] is not expected_exec:
        raise PrepareError("tmpfs")
    return parsed


def _require_tmpfs_match(parsed: dict, *, dest: str, size: int, inodes: int) -> None:
    if parsed.get("size") != size or parsed.get("nr_inodes") != inodes:
        raise PrepareError("tmpfs")


def validate_inspect_contract(
        inspect, *, sealed: bool, mount_spec=DEFAULT_MOUNT_SPEC,
        resource_profile=None) -> dict:
    """Refuse a container whose stored configuration contradicts the v1 fields of the profile.

    A v2 profile is admitted and read through the same v1 fields only. Its CPU and nofile values
    are deliberately not checked here: this runs after the container started, so a raise would
    record a run that happened as refused/not-run. They are compared by the envelope comparator,
    where a mismatch makes the envelope unverified and keeps the candidate outcome.
    """
    profile = require_versioned_resource_profile(
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
    owner_bound = profile["schema"] == RESOURCE_PROFILE_V2_SCHEMA
    parsed = {
        "/tmp": _tmpfs_spec(tmpfs.get("/tmp"), owner_bound=owner_bound),
        "/work": _tmpfs_spec(
            tmpfs.get("/work"), expected_exec=profile["work_exec"],
            owner_bound=owner_bound),
    }
    _require_tmpfs_match(
        parsed["/tmp"], dest="/tmp",
        size=profile["tmp_bytes"], inodes=profile["tmp_inodes"])
    _require_tmpfs_match(
        parsed["/work"], dest="/work",
        size=profile["work_bytes"], inodes=profile["work_inodes"])
    if not owner_bound:
        parsed = {
            destination: {"nr_inodes": value["nr_inodes"], "size": value["size"]}
            for destination, value in parsed.items()
        }
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
    return _contract_call(_contract.require_image_id, value)


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
    profile = require_versioned_resource_profile(
        INERT_RESOURCE_PROFILE if resource_profile is None else resource_profile)
    normalized_mount_spec = _require_mount_spec(mount_spec)
    expected_mounts = {key for key, _destination in normalized_mount_spec}
    if set(mounts) - expected_mounts:
        raise PrepareError("unexpected mount")
    owner_bound = profile["schema"] == RESOURCE_PROFILE_V2_SCHEMA
    tmp_tmpfs = encode_tmpfs_options(
        tmpfs_request(profile, destination="/tmp", owner_bound=owner_bound),
        owner_bound=owner_bound)
    work_tmpfs = encode_tmpfs_options(
        tmpfs_request(profile, destination="/work", owner_bound=owner_bound),
        owner_bound=owner_bound)
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
    # Only a v2 profile carries CPU and descriptor limits; a v1 argv is byte-identical to before.
    if profile["schema"] == RESOURCE_PROFILE_V2_SCHEMA:
        argv.extend(docker_resource_argv_v2(profile))
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


# Bounds for the kernel read-back (#197): each exec, and the wait for the held container to be
# running before the first read.
READBACK_EXEC_SECONDS = 15
READBACK_RUNNING_POLLS = 200
READBACK_RUNNING_POLL_SECONDS = 0.025
READBACK_RELEASE_ATTEMPTS = 3
# How long the host waits for a second hold's ready file: the witness forks to the limit, then
# waits for its children to be reaped, which takes a few seconds.
SECOND_HOLD_READY_POLLS = 1200


class DockerTransport:
    """Production transport for the bounded create/start/inspect/remove funnel."""

    skip_absent = False

    def create(self, argv):
        """Create under docker_bounded's success rule; return the create-time warnings."""
        proc = docker_ok(argv[1:])
        _required_stdout(proc)
        return create_warnings_from_stderr(proc.stderr)

    def start(self, name, deadline_seconds):
        if type(deadline_seconds) is not int or deadline_seconds <= 0:
            raise PrepareError("candidate deadline")
        return docker_run_capped(
            ["start", "-a", name], timeout=deadline_seconds)

    def inspect(self, name):
        return parse_inspect_payload(docker_bounded(["inspect", name]))

    def remove(self, name):
        docker_bounded(["rm", "-f", name])

    def running(self, name) -> bool:
        """Whether the daemon reports the container running now. Unknown is not running."""
        state = self.inspect(name).get("State")
        return type(state) is dict and state.get("Running") is True

    def exec_read(self, name, path):
        """One file read as the container user inside the held container, or None.

        Absence is not a value: any failure to read, including a timeout, is None, and the
        caller records it as unreadable.
        """
        try:
            proc = docker_run_capped(["exec", name, "cat", path], timeout=READBACK_EXEC_SECONDS)
        except (subprocess.TimeoutExpired, br._OutputTooLarge, PrepareError):
            return None
        if proc.returncode != 0 or not isinstance(proc.stdout, str):
            return None
        return proc.stdout.encode("utf-8")

    def release(self, name, path):
        """Let the held wrapper continue. False if the release could not be written."""
        try:
            proc = docker_run_capped(["exec", name, "touch", path], timeout=READBACK_EXEC_SECONDS)
        except (subprocess.TimeoutExpired, br._OutputTooLarge, PrepareError):
            return False
        return proc.returncode == 0

    def require_absent(self, name):
        require_container_absent(name)

    def version(self):
        return require_docker_ready()

    def daemon_info(self):
        """Explicit bounded daemon observation; readiness does not invoke this."""
        raw = docker_bounded(["info", "--format", "{{json .}}"] )
        value = load_strict(raw)
        if type(value) is not dict:
            raise PrepareError("daemon")
        return value

    def image_env_names(self, image_id):
        return image_env_names(image_id)


def resolve_transport(image_id: str, transport):
    """Return the injected transport or materialize the production transport once."""
    if transport is None:
        require_local_image(require_image_id(image_id))
        return DockerTransport()
    return transport


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


def observed_oom_killed(inspect):
    """`State.OOMKilled` as the daemon reported it: True or False, else None (not observed).

    An absent field, a missing or malformed State, or any value that is not a bool (the
    string "true", 1, 0) is None, never read as either answer. This is an observation, not a
    cause: containerd publishes TaskOOM when the cgroup's `memory.events` `oom_kill` counter
    rises, which counts processes killed by any OOM killer in that cgroup, a host-wide OOM
    included, and moby then sets the field. It does not say which process was killed.
    """
    state = inspect.get("State") if type(inspect) is dict else None
    value = state.get("OOMKilled") if type(state) is dict else None
    return value if type(value) is bool else None


def _release(transport, name: str, path: str) -> None:
    for _attempt in range(READBACK_RELEASE_ATTEMPTS):
        try:
            if transport.release(name, path):
                return
        except PrepareError:
            pass


def _start_with_readback(transport, name: str, deadline_seconds: int, second_hold=None):
    """Attach to the container as usual, and read the kernel's limits while it is held (#197).

    `start -a` runs in a helper thread exactly as it would alone, so its deadline and output
    cap are unchanged. Meanwhile this thread waits for the container to be running, reads each
    kernel file through the transport, and then releases the held wrapper. The release is
    attempted even when a read failed, so the run completes and is judged, rather than timing
    out in the hold. A file that did not read is None: never a value.

    `second_hold` is `(ready_path, paths, release_path)` for a wrapper that holds a second time,
    after its payload ran (the pids witness). Once the first release is done, this thread waits
    for the wrapper's ready file, reads `paths`, and releases `release_path`, again with the
    release attempted whatever the reads did. The files of both holds come back in one dict.
    """
    import kernel_readback  # inside the execution identity; imported where it is used
    import threading

    outcome = {}

    def attach():
        try:
            outcome["process"] = transport.start(name, deadline_seconds)
        except BaseException as exc:  # re-raised on this thread below, unchanged
            outcome["error"] = exc

    thread = threading.Thread(target=attach, name="contained-attach", daemon=True)
    thread.start()
    files = {key: None for key, _path in kernel_readback.READBACK_PATHS}
    if second_hold is not None:
        ready_path, second_paths, second_release = second_hold
        files.update({key: None for key, _path in second_paths})
    try:
        try:
            for _ in range(READBACK_RUNNING_POLLS):
                if not thread.is_alive():
                    break
                try:
                    if transport.running(name):
                        for key, path in kernel_readback.READBACK_PATHS:
                            files[key] = transport.exec_read(name, path)
                        break
                except PrepareError:
                    pass
                time.sleep(READBACK_RUNNING_POLL_SECONDS)
        finally:
            # Always try to release: a held wrapper nobody releases would wait out its own bound.
            # A few attempts, because one failed exec should not cost the run.
            _release(transport, name, kernel_readback.RELEASE_PATH)
        if second_hold is not None:
            try:
                for _ in range(SECOND_HOLD_READY_POLLS):
                    if not thread.is_alive():
                        break
                    try:
                        if transport.exec_read(name, ready_path) is not None:
                            for key, path in second_paths:
                                files[key] = transport.exec_read(name, path)
                            break
                    except PrepareError:
                        pass
                    time.sleep(READBACK_RUNNING_POLL_SECONDS)
            finally:
                _release(transport, name, second_release)
    finally:
        # In its own finally, so an unexpected read or release error never leaves the attach
        # thread unjoined.
        thread.join()
    if "error" in outcome:
        raise outcome["error"]
    return outcome["process"], files


def run_contained(
        *, image_id: str, mounts: dict, command: list[str], entrypoint: str,
        mount_spec, resource_profile, sealed: bool,
        name_prefix: str, transport=None, cleanup_label: str = "candidate",
        record_cleanup: bool = False, readback: bool = False, second_hold=None) -> dict:
    """Run one container and return its inspect-verified raw outcome.

    `record_cleanup` is for callers that keep an execution-envelope record:
    a cleanup failure after the candidate already ran becomes a recorded
    `cleanup` state instead of an exception that loses the run. Callers that
    keep no record leave it false and a cleanup failure still refuses.

    `create_warnings` is whatever `transport.create` returned, unjudged here:
    a tuple of warning lines, or None from a transport that observes none.
    `oom_killed` is `observed_oom_killed` of the same inspect, unjudged here too:
    no state or exit code is refused or reclassified because of it.
    """
    image_id = require_image_id(image_id)
    profile = require_versioned_resource_profile(resource_profile)
    transport = resolve_transport(image_id, transport)
    if getattr(transport, "skip_absent", False):
        raise PrepareError("absence proof skipped")
    if second_hold is not None and not readback:
        raise PrepareError("a second hold needs the read-back")
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
        create_warnings = transport.create(argv)
        kernel_files = None
        try:
            if readback:
                process, kernel_files = _start_with_readback(
                    transport, name, profile["deadline_seconds"], second_hold)
            else:
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
    raw = {
        "cleanup": cleanup,
        "container_absent_after": cleanup == "removed-and-absent",
        "contract": envelope,
        "create_warnings": create_warnings,
        "inspect": observed,
        "name": name,
        "oom_killed": observed_oom_killed(observed),
        "process": process,
        "state": state,
    }
    # Only a run that asked for the read-back carries it, so every other result keeps its shape.
    if readback:
        raw["kernel_files"] = kernel_files
    return raw


def observe_daemon_info(transport):
    """Explicit injected transport only; no readiness or emitter activation."""
    value = transport.daemon_info()
    if type(value) is not dict:
        raise PrepareError("daemon")
    return value
