"""Bounded pinned-archive materialization for PREPARE. Not a checker."""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import urllib.request
from pathlib import Path
from secrets import token_hex

import bounded_run as br
import corpus_adequacy as ca

from aee_checker_sealed_common import (
    EMPTY_SHA256,
    FROZEN_CORPUS_MANIFEST_SHA256,
    FROZEN_CORPUS_TREE_SHA256,
    FROZEN_SUBJECT_TREE_SHA256,
    MATERIALIZE_CEILINGS,
    MaterializeBudget,
    PrepareError,
    exact_object,
    load_strict,
    verify_file_digest,
)
from aee_checker_sealed_oci import (
    docker_bounded,
    docker_ok,
    parse_inspect_payload,
    require_container_absent,
    require_image_id,
)

MATERIALIZE_CAP_BYTES = MATERIALIZE_CEILINGS["disk_bytes"]
MATERIALIZE_CAP_FILES = MATERIALIZE_CEILINGS["entry_count"]
MATERIALIZE_DEADLINE_SECONDS = MATERIALIZE_CEILINGS["deadline_seconds"]
CORPUS_ID_COUNT = 250
CARGO_CONFIG_NAME = "config.toml"
VENDOR_CONFIG_REL = "../vendor"
RUST_IMAGE = (
    "docker.io/library/rust@sha256:"
    "e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2"
)
RUSTC_RELEASE = "1.92.0"
VENDOR_TOOLCHAIN_KEYS = (
    "cargo_V", "image_id", "index", "observation", "platform", "rustc_Vv",
)
COPY_CHUNK_BYTES = 65536


def _note_cleanup_failure(primary: BaseException, action: str,
                          failure: BaseException) -> None:
    primary.add_note("%s failed: %s: %s" % (
        action, type(failure).__name__, failure))


def _unlink_preserving(dest: Path, primary: BaseException) -> None:
    if not dest.exists():
        return
    try:
        dest.unlink()
    except OSError as exc:
        _note_cleanup_failure(primary, "download cleanup", exc)


def require_vendor_outside(subject: Path, vendor: Path) -> None:
    subject, vendor = Path(subject).resolve(), Path(vendor).resolve()
    try:
        vendor.relative_to(subject)
    except ValueError:
        return
    raise PrepareError("vendor must be outside the subject root")


def _budget(budget, cap_bytes=None, cap_files=None, deadline_seconds=None):
    if budget is not None:
        return budget
    spec = dict(MATERIALIZE_CEILINGS)
    if cap_bytes is not None:
        spec["disk_bytes"] = cap_bytes
    if cap_files is not None:
        spec["entry_count"] = cap_files
    if deadline_seconds is not None:
        spec["deadline_seconds"] = deadline_seconds
    return MaterializeBudget(spec)


def tree_sha256(
        root: Path, *, cap_bytes: int = MATERIALIZE_CAP_BYTES,
        cap_files: int = MATERIALIZE_CAP_FILES, budget=None) -> str:
    root = Path(root)
    limit_bytes = budget.remaining_bytes() if budget is not None else cap_bytes
    limit_entries = budget.remaining_entries() if budget is not None else cap_files
    entries = []
    files = 0
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + filenames:
            path = Path(dirpath) / name
            if path.is_symlink():
                raise PrepareError("symlink in tree")
            rel = path.relative_to(root).as_posix()
            if path.is_dir():
                entries.append((rel, "dir", b""))
            elif path.is_file():
                try:
                    raw = ca.read_bounded_regular_file(path, cap=limit_bytes - total)
                except ca.ManifestError as exc:
                    raise PrepareError(str(exc)) from exc
                entries.append((rel, "file", raw))
                files += 1
                total += len(raw)
            else:
                raise PrepareError("non-regular in tree")
            if len(entries) > limit_entries:
                raise PrepareError("tree exceeds entry ceiling")
            if total > limit_bytes:
                raise PrepareError("tree exceeds byte ceiling")
    if files == 0:
        raise PrepareError("empty tree")
    digest = hashlib.sha256()
    for rel, kind, raw in sorted(entries, key=lambda item: item[0]):
        digest.update(rel.encode("utf-8"))
        if kind == "dir":
            digest.update(b"\0dir\0")
            continue
        digest.update(b"\0")
        digest.update(str(len(raw)).encode("ascii"))
        digest.update(b"\0")
        digest.update(raw)
    return digest.hexdigest()


def download_bounded(
        url: str, dest: Path, *, cap_bytes: int = MATERIALIZE_CAP_BYTES,
        deadline_seconds: int = MATERIALIZE_DEADLINE_SECONDS, budget=None) -> Path:
    dest = Path(dest)
    if dest.exists():
        raise PrepareError("download dest exists")
    dest.parent.mkdir(parents=True, exist_ok=True)
    budget = _budget(budget, cap_bytes, None, deadline_seconds)
    written = 0
    try:
        budget.charge(entries=1)
        with urllib.request.urlopen(url, timeout=deadline_seconds) as resp:
            with dest.open("wb") as out:
                while True:
                    budget.check_deadline()
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    budget.charge(bytes=len(chunk))
                    written += len(chunk)
                    out.write(chunk)
    except PrepareError as exc:
        _unlink_preserving(dest, exc)
        raise
    except Exception as exc:
        primary = PrepareError("download failed")
        _unlink_preserving(dest, primary)
        raise primary from exc
    if written == 0:
        primary = PrepareError("download empty")
        _unlink_preserving(dest, primary)
        raise primary
    return dest


def archive_member_rel(name: str):
    text = str(name).replace("\\", "/")
    if text.startswith("/") or text.startswith("../"):
        raise PrepareError("archive path traversal")
    parts = [part for part in text.split("/") if part]
    if not parts or any(part == ".." for part in parts):
        raise PrepareError("archive path traversal")
    rel = "/".join(parts[1:])
    if not rel:
        return None
    if Path(rel).is_absolute() or ".." in Path(rel).parts:
        raise PrepareError("archive path traversal")
    return rel


def refuse_archive_link(info) -> None:
    if info.issym() or info.islnk():
        raise PrepareError("archive link escape")


def refuse_duplicate_member(seen: set, rel: str) -> None:
    if rel in seen:
        raise PrepareError("duplicate archive member")
    seen.add(rel)


def stream_archive_member(source, dest: Path, header_size, remaining: int) -> int:
    if type(header_size) is not int or header_size < 0:
        raise PrepareError("extract size")
    if header_size > remaining:
        raise PrepareError("extract exceeds byte ceiling")
    dest.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with dest.open("wb") as out:
        while written < header_size:
            chunk = source.read(min(COPY_CHUNK_BYTES, header_size - written))
            if not chunk:
                raise PrepareError("extract size")
            out.write(chunk)
            written += len(chunk)
        extra = source.read(1)
        if extra:
            raise PrepareError("extract size")
    return written


def extract_pinned_archive(
        archive: Path, dest: Path, *, cap_bytes: int = MATERIALIZE_CAP_BYTES,
        cap_files: int = MATERIALIZE_CAP_FILES, budget=None) -> Path:
    dest = Path(dest)
    if dest.exists():
        raise PrepareError("extract dest exists")
    dest.mkdir(parents=True)
    budget = _budget(budget, cap_bytes, cap_files)
    files = 0
    seen = set()
    with tarfile.open(archive, "r:*") as tar:
        for info in tar:
            budget.check_deadline()
            rel = archive_member_rel(info.name)
            if rel is None:
                continue
            refuse_archive_link(info)
            refuse_duplicate_member(seen, rel)
            budget.charge(entries=1)
            if info.isdir():
                (dest / rel).mkdir(parents=True, exist_ok=True)
                continue
            if not info.isreg():
                raise PrepareError("non-regular in archive")
            source = tar.extractfile(info)
            if source is None:
                raise PrepareError("extract missing")
            written = stream_archive_member(
                source, dest / rel, info.size, budget.remaining_bytes())
            budget.charge(bytes=written)
            files += 1
    if files == 0:
        raise PrepareError("empty archive")
    return dest


def pinned_archive_url(repository: str, commit: str) -> str:
    return "https://github.com/%s/archive/%s.tar.gz" % (repository, commit)


def require_frozen_manifest_sha(raw: bytes) -> str:
    digest = hashlib.sha256(raw).hexdigest()
    if digest != FROZEN_CORPUS_MANIFEST_SHA256:
        raise PrepareError("corpus manifest sha mismatch")
    return digest


def require_frozen_trees(subject_digest: str, corpus_digest: str) -> None:
    if subject_digest != FROZEN_SUBJECT_TREE_SHA256:
        raise PrepareError("subject tree digest mismatch")
    if corpus_digest != FROZEN_CORPUS_TREE_SHA256:
        raise PrepareError("corpus tree digest mismatch")


def require_corpus_id_set(ids) -> None:
    if type(ids) is not list or len(ids) != CORPUS_ID_COUNT or len(set(ids)) != CORPUS_ID_COUNT:
        raise PrepareError("corpus must list exactly %d unique ids" % CORPUS_ID_COUNT)


def verify_materialized(pins: dict, subject: Path, corpus: Path) -> dict:
    check = Path(subject) / pins["subject"]["path"]
    raw = verify_file_digest(check, pins["subject"]["check_rs_sha256"])
    manifest_path = Path(corpus) / "vectors" / "MANIFEST.json"
    try:
        manifest_raw = ca.read_bounded_regular_file(manifest_path)
    except ca.ManifestError as exc:
        raise PrepareError(str(exc)) from exc
    require_frozen_manifest_sha(manifest_raw)
    manifest = load_strict(manifest_raw)
    if manifest.get("corpusDigest") != pins["corpus"]["corpusDigest"]:
        raise PrepareError("corpus digest mismatch")
    ids = []
    seen = set()
    for row in manifest.get("vectors") or []:
        if type(row) is not dict or not isinstance(row.get("id"), str):
            raise PrepareError("corpus vector id")
        if row["id"] in seen:
            raise PrepareError("duplicate corpus id")
        seen.add(row["id"])
        ids.append(row["id"])
        rel = row.get("file")
        if not isinstance(rel, str) or not rel or rel.startswith("/") or ".." in Path(rel).parts:
            raise PrepareError("corpus vector file")
        listed = Path(corpus) / "vectors" / rel
        if listed.is_symlink() or not listed.is_file():
            raise PrepareError("listed vector file missing")
    require_corpus_id_set(ids)
    subject_tree = tree_sha256(subject)
    corpus_tree = tree_sha256(corpus)
    require_frozen_trees(subject_tree, corpus_tree)
    return {
        "corpus_digest": manifest["corpusDigest"],
        "corpus_id_count": len(ids),
        "corpus_id_set_sha256": hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest(),
        "corpus_manifest_sha256": FROZEN_CORPUS_MANIFEST_SHA256,
        "corpus_tree_sha256": corpus_tree,
        "subject_binary": False,
        "subject_check_rs_sha256": hashlib.sha256(raw).hexdigest(),
        "subject_tree_sha256": subject_tree,
    }


def bind_vendor_config(tool: Path, template: Path) -> str:
    tool = Path(tool)
    tool.mkdir(parents=True, exist_ok=True)
    dest = tool / CARGO_CONFIG_NAME
    try:
        raw = ca.read_bounded_regular_file(Path(template))
    except ca.ManifestError as exc:
        raise PrepareError(str(exc)) from exc
    if b"directory = \"%s\"" % VENDOR_CONFIG_REL.encode("ascii") not in raw:
        raise PrepareError("vendor config must replace crates-io with ../vendor")
    dest.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def charge_existing_tree(root: Path, budget: MaterializeBudget) -> None:
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + filenames:
            path = Path(dirpath) / name
            if path.is_symlink():
                raise PrepareError("symlink in tree")
            budget.charge(entries=1)
            if path.is_dir():
                continue
            if not path.is_file():
                raise PrepareError("non-regular in tree")
            try:
                raw = ca.read_bounded_regular_file(path, cap=budget.remaining_bytes())
            except ca.ManifestError as exc:
                raise PrepareError(str(exc)) from exc
            budget.charge(bytes=len(raw))


def require_vendor_toolchain(doc) -> dict:
    exact_object(doc, VENDOR_TOOLCHAIN_KEYS, "toolchain")
    if doc.get("observation") != "vendor-image; checker was not run":
        raise PrepareError("toolchain must come from the vendor image")
    require_image_id(doc.get("image_id"))
    if doc.get("index") != RUST_IMAGE:
        raise PrepareError("rust image index")
    if RUSTC_RELEASE not in str(doc.get("rustc_Vv") or ""):
        raise PrepareError("rustc provenance")
    if RUSTC_RELEASE not in str(doc.get("cargo_V") or ""):
        raise PrepareError("cargo provenance")
    if not str(doc.get("platform") or "").startswith("linux/"):
        raise PrepareError("rust image platform")
    return doc


def _observe_image_cmd(image_id: str, command: list[str]) -> str:
    proc = br._run_capped(
        ["docker", "run", "--rm", "--network", "none", image_id, *command],
        Path.cwd(), 30)
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        raise PrepareError("toolchain observation failed")
    return proc.stdout


def pull_rust_image(*, budget=None) -> dict:
    budget = _budget(budget)
    budget.check_deadline()
    if "@sha256:" not in RUST_IMAGE:
        raise PrepareError("rust image must be a digest")
    proc = br._run_capped(
        ["docker", "pull", RUST_IMAGE], Path.cwd(), MATERIALIZE_DEADLINE_SECONDS)
    if proc.returncode != 0:
        raise PrepareError("rust image pull failed")
    inspect = parse_inspect_payload(docker_bounded(["image", "inspect", RUST_IMAGE]))
    image_id = require_image_id(str(inspect.get("Id") or ""))
    os_name, arch = inspect.get("Os"), inspect.get("Architecture")
    if not os_name or not arch:
        raise PrepareError("rust image platform")
    rustc = _observe_image_cmd(image_id, ["rustc", "-Vv"])
    cargo = _observe_image_cmd(image_id, ["cargo", "-V"])
    return require_vendor_toolchain({
        "cargo_V": cargo.strip(),
        "image_id": image_id,
        "index": RUST_IMAGE,
        "observation": "vendor-image; checker was not run",
        "platform": "%s/%s" % (os_name, arch),
        "rustc_Vv": rustc,
    })


def vendor_create_argv(*, name: str, subject: Path, vendor: Path, budget=None) -> list[str]:
    size = budget.remaining_bytes() if budget is not None else MATERIALIZE_CAP_BYTES
    inodes = budget.remaining_entries() if budget is not None else MATERIALIZE_CAP_FILES
    tmpfs = "rw,size=%d,nr_inodes=%d" % (size, inodes)
    return [
        "docker", "create",
        "--name", name,
        "--network", "bridge",
        "--tmpfs", "/vendor:%s" % tmpfs,
        "--mount",
        "type=bind,source=%s,destination=/src,readonly" % Path(subject).resolve(),
        "--mount",
        "type=bind,source=%s,destination=/out" % Path(vendor).resolve(),
        "--workdir", "/src",
        RUST_IMAGE,
        "sleep", str(MATERIALIZE_DEADLINE_SECONDS),
    ]


def host_bind_owner(dest: Path) -> str:
    info = Path(dest).stat()
    uid, gid = info.st_uid, info.st_gid
    if type(uid) is not int or type(gid) is not int or uid < 0 or gid < 0:
        raise PrepareError("host bind owner is not readable")
    return "%d:%d" % (uid, gid)


def copy_tmpfs_argv(name: str, owner: str) -> list[str]:
    if owner.count(":") != 1:
        raise PrepareError("host bind owner is not readable")
    uid, gid = owner.split(":")
    if not uid.isdigit() or not gid.isdigit():
        raise PrepareError("host bind owner is not readable")
    return [
        "exec", "--user", owner, name,
        "cp", "-R", "--no-preserve=ownership", "/vendor/.", "/out/",
    ]


def copy_tmpfs_as_bind_owner(name: str, dest: Path) -> None:
    docker_ok(copy_tmpfs_argv(name, host_bind_owner(dest)))


def vendor_locked(subject: Path, vendor: Path, *, budget=None, toolchain=None) -> dict:
    require_vendor_outside(subject, vendor)
    vendor = Path(vendor)
    vendor.mkdir(parents=True, exist_ok=True)
    owner = host_bind_owner(vendor)
    budget = _budget(budget)
    if toolchain is None:
        toolchain = pull_rust_image(budget=budget)
    require_vendor_toolchain(toolchain)
    name = "aee-vendor-%s" % token_hex(4)
    created = False
    try:
        docker_bounded(vendor_create_argv(
            name=name, subject=subject, vendor=vendor, budget=budget)[1:])
        created = True
        docker_bounded(["start", name])
        proc = br._run_capped(
            ["docker", "exec", name, "cargo", "vendor", "--locked", "/vendor"],
            Path.cwd(),
            budget.ceilings["deadline_seconds"],
        )
        if proc.returncode != 0:
            raise PrepareError("cargo vendor --locked failed")
        docker_ok(copy_tmpfs_argv(name, owner))
    finally:
        if created:
            try:
                docker_ok(["rm", "-f", name])
            except PrepareError as exc:
                require_container_absent(name)
                raise PrepareError("container remove failed") from exc
    require_container_absent(name)
    charge_existing_tree(vendor, budget)
    digest = tree_sha256(vendor)
    if digest == EMPTY_SHA256:
        raise PrepareError("empty vendor")
    return {"toolchain": toolchain, "vendor_sha256": digest}


def materialize_pinned(pins: dict, dest: Path, *, template: Path, budget=None) -> dict:
    dest = Path(dest)
    budget = _budget(budget)
    subject, corpus, vendor, tool = dest / "subject", dest / "corpus", dest / "vendor", dest / "tool"
    archives = dest / "archives"
    archives.mkdir()
    subject_tar = download_bounded(
        pinned_archive_url(pins["subject"]["repository"], pins["subject"]["commit"]),
        archives / "subject.tar.gz", budget=budget)
    corpus_tar = download_bounded(
        pinned_archive_url(pins["corpus"]["repository"], pins["corpus"]["commit"]),
        archives / "corpus.tar.gz", budget=budget)
    extract_pinned_archive(subject_tar, subject, budget=budget)
    extract_pinned_archive(corpus_tar, corpus, budget=budget)
    shutil.rmtree(archives)
    verified = verify_materialized(pins, subject, corpus)
    verified["vendor_outside_subject"] = True
    toolchain = pull_rust_image(budget=budget)
    vendored = vendor_locked(subject, vendor, budget=budget, toolchain=toolchain)
    verified["vendor_sha256"] = vendored["vendor_sha256"]
    verified["toolchain"] = vendored["toolchain"]
    verified["tool_config_sha256"] = bind_vendor_config(tool, template)
    verified["subject"] = subject
    verified["corpus"] = corpus
    verified["vendor"] = vendor
    verified["tool"] = tool
    return verified


def _fsync_tree(root: Path) -> None:
    """Best-effort flush only; no durability, crash, or power-loss guarantee."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            path = Path(dirpath) / name
            try:
                fd = os.open(str(path), os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError:
                continue
        try:
            fd = os.open(dirpath, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            continue


def begin_atomic_dest(dest: Path) -> dict:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise PrepareError("dest exists")
    lease = dest.with_name(dest.name + ".lease")
    token = token_hex(16)
    try:
        fd = os.open(str(lease), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise PrepareError("dest lease exists") from None
    try:
        os.write(fd, token.encode("ascii"))
    finally:
        os.close(fd)
    staging = dest.with_name("%s.tmp-%s" % (dest.name, token_hex(8)))
    try:
        staging.mkdir()
    except FileExistsError:
        _release_owned_lease(lease, token)
        raise PrepareError("dest staging exists") from None
    return {"dest": dest, "lease": lease, "staging": staging, "token": token}


def _release_owned_lease(lease: Path, token: str) -> None:
    lease = Path(lease)
    if not lease.is_file():
        return
    try:
        raw = lease.read_bytes()
    except OSError:
        return
    if raw != token.encode("ascii"):
        return
    try:
        lease.unlink()
    except OSError:
        return


def commit_atomic_dest(state: dict) -> Path:
    dest = Path(state["dest"])
    staging = Path(state["staging"])
    # os.rename is deliberate: lease plus dest precheck is the exclusion boundary.
    # POSIX may replace an empty target; residual TOCTOU is accepted. This makes
    # no exclusive-create claim and never authorizes removing a foreign dest.
    if dest.exists():
        primary = PrepareError("dest exists")
        try:
            abort_atomic_dest(state)
        except BaseException as exc:
            _note_cleanup_failure(primary, "atomic abort", exc)
        raise primary
    _fsync_tree(staging)
    try:
        os.rename(str(staging), str(dest))
    except OSError as exc:
        primary = PrepareError("dest exists")
        try:
            abort_atomic_dest(state)
        except BaseException as cleanup_exc:
            _note_cleanup_failure(primary, "atomic abort", cleanup_exc)
        raise primary from exc
    _release_owned_lease(state["lease"], state["token"])
    return dest


def abort_atomic_dest(state: dict) -> None:
    dest = Path(state["dest"])
    staging = Path(state["staging"])
    if staging.exists() and staging.resolve() != dest.resolve():
        shutil.rmtree(staging)
    _release_owned_lease(state["lease"], state["token"])
