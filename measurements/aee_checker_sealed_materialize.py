"""Bounded pinned-archive materialization for PREPARE. Not a checker."""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import urllib.request
from pathlib import Path
from secrets import token_hex

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
    preserve_cleanup_failure,
    verify_file_digest,
)
from aee_checker_sealed_oci import (
    cleanup_container,
    docker_bounded,
    docker_ok,
    docker_run_capped,
    parse_inspect_payload,
    require_container_absent,
    require_image_id,
)
from sealed_measurement_contract import AEE_CHECKER_SEALED_CONTRACT

MATERIALIZE_CAP_BYTES = MATERIALIZE_CEILINGS["disk_bytes"]
MATERIALIZE_CAP_FILES = MATERIALIZE_CEILINGS["entry_count"]
MATERIALIZE_DEADLINE_SECONDS = MATERIALIZE_CEILINGS["deadline_seconds"]
CORPUS_ID_COUNT = AEE_CHECKER_SEALED_CONTRACT.corpus_id_count
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
READONLY_BIND_DIRECTORY_MODE = 0o755
READONLY_BIND_FILE_MODE = 0o644


def normalize_readonly_bind_modes(root: Path) -> None:
    """Make one verified bind tree readable by the container's distinct uid."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        directory = Path(dirpath)
        if directory.is_symlink() or not directory.is_dir():
            raise PrepareError("non-regular in readonly bind tree")
        directory.chmod(READONLY_BIND_DIRECTORY_MODE)
        for name in dirnames:
            path = directory / name
            if path.is_symlink() or not path.is_dir():
                raise PrepareError("non-regular in readonly bind tree")
        for name in filenames:
            path = directory / name
            if path.is_symlink() or not path.is_file():
                raise PrepareError("non-regular in readonly bind tree")
            path.chmod(READONLY_BIND_FILE_MODE)


def _unlink_preserving(dest: Path, primary: BaseException) -> None:
    if not dest.exists():
        return
    try:
        dest.unlink()
    except OSError as exc:
        preserve_cleanup_failure(primary, "download cleanup", exc)


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
        cap_files: int = MATERIALIZE_CAP_FILES, budget=None,
        allow_canonical_empty: bool = False) -> str:
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
    if files == 0 and not (allow_canonical_empty and not entries):
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


def require_vendor_tree_digest(
        digest: str, *, contract=AEE_CHECKER_SEALED_CONTRACT) -> str:
    empty = digest == EMPTY_SHA256
    if contract.vendor_tree_requirement == "nonempty":
        if empty:
            raise PrepareError("empty vendor")
    elif contract.vendor_tree_requirement == "canonical-empty":
        if not empty:
            raise PrepareError("vendor must be empty")
    else:  # A contract instance validates this, but refuse foreign duck types too.
        raise PrepareError("vendor tree requirement")
    return digest


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
    except BaseException as primary:
        _unlink_preserving(dest, primary)
        raise
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
        cap_files: int = MATERIALIZE_CAP_FILES, budget=None,
        selected_subdir: str | None = None) -> Path:
    dest = Path(dest)
    if dest.exists():
        raise PrepareError("extract dest exists")
    dest.mkdir(parents=True)
    budget = _budget(budget, cap_bytes, cap_files)
    files = 0
    seen = set()
    archive_seen = set()
    with tarfile.open(archive, "r:*") as tar:
        for info in tar:
            budget.check_deadline()
            rel = archive_member_rel(info.name)
            if rel is None:
                if selected_subdir is not None:
                    refuse_archive_link(info)
                    budget.charge(entries=1)
                    if not info.isdir():
                        raise PrepareError("non-regular in archive")
                continue
            refuse_archive_link(info)
            # A selected extraction still admits every archive header before deciding
            # whether it belongs to the destination subtree.
            if selected_subdir is not None:
                refuse_duplicate_member(archive_seen, rel)
                budget.charge(entries=1)
                if info.isreg():
                    if type(info.size) is not int or info.size < 0:
                        raise PrepareError("extract size")
                    budget.charge(bytes=info.size)
                elif not info.isdir():
                    raise PrepareError("non-regular in archive")
                prefix = selected_subdir + "/"
                if rel == selected_subdir:
                    continue
                if not rel.startswith(prefix):
                    continue
                rel = rel[len(prefix):]
                if not rel:
                    continue
            refuse_duplicate_member(seen, rel)
            if selected_subdir is None:
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
                source, dest / rel, info.size,
                info.size if selected_subdir is not None else budget.remaining_bytes())
            if selected_subdir is None:
                budget.charge(bytes=written)
            files += 1
    if files == 0:
        raise PrepareError("empty archive")
    return dest


def pinned_archive_url(repository: str, commit: str) -> str:
    return "https://github.com/%s/archive/%s.tar.gz" % (repository, commit)


def require_frozen_manifest_sha(raw: bytes, *, contract=AEE_CHECKER_SEALED_CONTRACT) -> str:
    digest = hashlib.sha256(raw).hexdigest()
    if digest != contract.corpus_manifest_sha256:
        raise PrepareError("corpus manifest sha mismatch")
    return digest


def require_frozen_trees(subject_digest: str, corpus_digest: str,
                         *, contract=AEE_CHECKER_SEALED_CONTRACT) -> None:
    if subject_digest != contract.subject_tree_sha256:
        raise PrepareError("subject tree digest mismatch")
    if corpus_digest != contract.corpus_tree_sha256:
        raise PrepareError("corpus tree digest mismatch")


def require_corpus_id_set(ids, *, contract=AEE_CHECKER_SEALED_CONTRACT) -> None:
    count = contract.corpus_id_count
    if type(ids) is not list or len(ids) != count or len(set(ids)) != count:
        raise PrepareError("corpus must list exactly %d unique ids" % count)


def verify_materialized(pins: dict, subject: Path, corpus: Path,
                        *, contract=AEE_CHECKER_SEALED_CONTRACT) -> dict:
    check = Path(subject) / pins["subject"]["path"]
    raw = verify_file_digest(check, pins["subject"]["check_rs_sha256"])
    manifest_path = Path(corpus) / "vectors" / "MANIFEST.json"
    try:
        manifest_raw = ca.read_bounded_regular_file(manifest_path)
    except ca.ManifestError as exc:
        raise PrepareError(str(exc)) from exc
    require_frozen_manifest_sha(manifest_raw, contract=contract)
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
    require_corpus_id_set(ids, contract=contract)
    subject_tree = tree_sha256(subject)
    corpus_tree = tree_sha256(corpus)
    require_frozen_trees(subject_tree, corpus_tree, contract=contract)
    return {
        "corpus_digest": manifest["corpusDigest"],
        "corpus_id_count": len(ids),
        "corpus_id_set_sha256": hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest(),
        "corpus_manifest_sha256": contract.corpus_manifest_sha256,
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
    proc = docker_run_capped(
        ["run", "--rm", "--network", "none", image_id, *command],
        timeout=30)
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        raise PrepareError("toolchain observation failed")
    return proc.stdout


def pull_rust_image(*, budget=None) -> dict:
    budget = _budget(budget)
    budget.check_deadline()
    if "@sha256:" not in RUST_IMAGE:
        raise PrepareError("rust image must be a digest")
    proc = docker_run_capped(
        ["pull", RUST_IMAGE], timeout=MATERIALIZE_DEADLINE_SECONDS)
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


class _VendorCleanupTransport:
    def remove(self, name: str) -> None:
        docker_ok(["rm", "-f", name])

    def require_absent(self, name: str) -> None:
        require_container_absent(name)


def vendor_locked(subject: Path, vendor: Path, *, budget=None, toolchain=None,
                  contract=AEE_CHECKER_SEALED_CONTRACT) -> dict:
    require_vendor_outside(subject, vendor)
    vendor = Path(vendor)
    vendor.mkdir(parents=True, exist_ok=True)
    owner = host_bind_owner(vendor)
    budget = _budget(budget)
    if toolchain is None:
        toolchain = pull_rust_image(budget=budget)
    require_vendor_toolchain(toolchain)
    name = "aee-vendor-%s" % token_hex(4)
    cleanup = _VendorCleanupTransport()
    try:
        docker_bounded(vendor_create_argv(
            name=name, subject=subject, vendor=vendor, budget=budget)[1:])
        docker_bounded(["start", name])
        proc = docker_run_capped(
            ["exec", name, "cargo", "vendor", "--locked", "/vendor"],
            timeout=budget.ceilings["deadline_seconds"],
        )
        if proc.returncode != 0:
            raise PrepareError("cargo vendor --locked failed")
        docker_ok(copy_tmpfs_argv(name, owner))
    except BaseException as exc:
        cleanup_container(cleanup, name, exc, "vendor")
        raise
    cleanup_container(cleanup, name, None, "vendor")
    charge_existing_tree(vendor, budget)
    digest = require_vendor_tree_digest(
        tree_sha256(vendor, allow_canonical_empty=True), contract=contract)
    return {"toolchain": toolchain, "vendor_sha256": digest}


def materialize_pinned(pins: dict, dest: Path, *, template: Path, budget=None,
                       contract=AEE_CHECKER_SEALED_CONTRACT) -> dict:
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
    extract_pinned_archive(
        subject_tar, subject, budget=budget,
        selected_subdir=contract.subject_subdir)
    extract_pinned_archive(
        corpus_tar, corpus, budget=budget,
        selected_subdir=contract.corpus_subdir)
    shutil.rmtree(archives)
    verified = verify_materialized(pins, subject, corpus, contract=contract)
    verified["vendor_outside_subject"] = True
    toolchain = pull_rust_image(budget=budget)
    vendored = vendor_locked(
        subject, vendor, budget=budget, toolchain=toolchain, contract=contract)
    verified["vendor_sha256"] = vendored["vendor_sha256"]
    verified["toolchain"] = vendored["toolchain"]
    verified["tool_config_sha256"] = bind_vendor_config(tool, template)
    for readonly_bind in (subject, corpus, vendor, tool):
        normalize_readonly_bind_modes(readonly_bind)
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
    # POSIX may replace an empty target; Windows refuses an existing target.
    # Residual TOCTOU is accepted. This makes no exclusive-create claim and never
    # authorizes removing a foreign dest.
    if dest.exists():
        primary = PrepareError("dest exists")
        try:
            abort_atomic_dest(state)
        except BaseException as exc:
            preserve_cleanup_failure(primary, "atomic abort", exc)
        raise primary
    _fsync_tree(staging)
    try:
        os.rename(str(staging), str(dest))
    except OSError as exc:
        primary = PrepareError("dest exists")
        try:
            abort_atomic_dest(state)
        except BaseException as cleanup_exc:
            preserve_cleanup_failure(primary, "atomic abort", cleanup_exc)
        raise primary from exc
    _release_owned_lease(state["lease"], state["token"])
    return dest


def abort_atomic_dest(state: dict) -> None:
    dest = Path(state["dest"])
    staging = Path(state["staging"])
    if staging.exists() and staging.resolve() != dest.resolve():
        shutil.rmtree(staging)
    _release_owned_lease(state["lease"], state["token"])


def _assessment_tree_snapshot(path, budget, *, empty=False):
    """Bounded no-follow snapshot before copying local preparation material."""
    import stat
    import suggestion_readback as reader
    import suggestion_evidence as ev
    reader._require_support()
    files = {}; directories = []; seen = set()
    def visit(parts, prefix):
        budget.check_deadline()
        with reader._directory(parts) as fd:
            names = sorted(os.listdir(fd))
            for name in names:
                budget.charge(entries=1)
                if name in ('.', '..') or '/' in name or '\\' in name:
                    ev.refuse('filesystem', 'unsafe-member')
                rel = prefix+name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    directories.append(rel)
                    visit(parts+(name,), rel+'/')
                else:
                    raw = reader._read_file(fd,name,remaining=budget.remaining_bytes(),cap=budget.remaining_bytes(),seen=seen)
                    budget.charge(bytes=len(raw)); files[rel]=raw
    visit(reader._absolute_parts(path), '')
    if not files and not (empty and not directories):
        raise PrepareError('empty assessment tree')
    return files, tuple(directories)


def _write_assessment_tree(snapshot, dest):
    files, directories = snapshot
    dest.mkdir()
    for name in directories:
        (dest/name).mkdir(parents=True,exist_ok=True)
    for name, raw in files.items():
        path=dest/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)


def observe_local_assessment_toolchain(expected):
    """No pull/build/cache fallback. Observe exactly the supplied local image."""
    require_vendor_toolchain(expected)
    image_id=expected['image_id']
    inspect=parse_inspect_payload(docker_bounded(['image','inspect',image_id]))
    actual={'image_id':require_image_id(inspect.get('Id')),
        'platform':str(inspect.get('Os'))+'/'+str(inspect.get('Architecture')),
        'rustc_Vv':_observe_image_cmd(image_id,['rustc','-Vv']),
        'cargo_V':_observe_image_cmd(image_id,['cargo','-V']).strip(),
        'index':RUST_IMAGE,'observation':'vendor-image; checker was not run'}
    require_vendor_toolchain(actual)
    if actual != expected:
        raise PrepareError('local assessment toolchain drift')
    return actual


def _assessment_materialized(dest, *, variant, plan):
    from sealed_measurement_contract import OWNED_INDEPENDENT_V0_CONTRACT as owned
    row=next(item for item in plan['variants'] if item['variant']==variant)
    result={key:Path(dest)/key for key in ('subject','corpus','vendor','tool')}
    result.update(subject_tree_sha256=tree_sha256(result['subject']),
        corpus_tree_sha256=tree_sha256(result['corpus']/'vectors'),
        corpus_manifest_sha256=hashlib.sha256((result['corpus']/'vectors/MANIFEST.json').read_bytes()).hexdigest(),
        corpus_id_count=5, vendor_sha256=tree_sha256(result['vendor'],allow_canonical_empty=True),
        tool_sha256=tree_sha256(result['tool']))
    if (result['subject_tree_sha256']!=owned.subject_tree_sha256
            or result['corpus_tree_sha256']!=row['tree_sha256']
            or result['corpus_manifest_sha256']!=row['manifest']['sha256']
            or result['vendor_sha256']!=EMPTY_SHA256):
        raise PrepareError('assessment materialization drift')
    return result


def materialize_owned_assessment(inputs_dir, dest, *, retained_members, variant, template):
    """Derive preparation trees solely from bounded local inputs and admitted plan."""
    import tempfile
    import suggestion_evidence as ev
    import suggestion_readback as reader
    from sealed_measurement_contract import OWNED_INDEPENDENT_V0_CONTRACT as owned
    budget=MaterializeBudget(MATERIALIZE_CEILINGS)
    parts=reader._absolute_parts(inputs_dir)
    with reader._directory(parts) as fd:
        reader._inventory(fd,('subject.tar.gz','toolchain.json','vendor'))
        archive=reader._read_file(fd,'subject.tar.gz',remaining=budget.remaining_bytes(),cap=budget.remaining_bytes(),seen=set())
        budget.charge(bytes=len(archive),entries=1)
        toolchain_raw=reader._read_file(fd,'toolchain.json',remaining=65536,seen=set())
    with reader._directory(parts+('vendor',)) as fd:
        reader._inventory(fd,())
    toolchain=require_vendor_toolchain(ev.decode(toolchain_raw,canonical=True))
    members=dict(retained_members);plan=ev.decode(members['plan.json'],canonical=True)
    if variant not in ev.VARIANTS:ev.refuse('binding','plan-variant')
    dest=Path(dest);dest.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        archive_path=Path(temp)/'subject.tar.gz';archive_path.write_bytes(archive)
        extract_pinned_archive(archive_path,dest/'subject',budget=budget,selected_subdir=owned.subject_subdir)
    (dest/'vendor').mkdir();(dest/'corpus/vectors').mkdir(parents=True)
    prefix=variant+'/corpus/'
    for name,raw in members.items():
        if name.startswith(prefix):
            budget.charge(entries=1,bytes=len(raw))
            path=dest/'corpus/vectors'/name[len(prefix):]
            with path.open('xb') as stream:stream.write(raw)
    bind_vendor_config(dest/'tool',template)
    result=_assessment_materialized(dest,variant=variant,plan=plan)
    if result['tool_sha256']!=ev._TOOL_TREE_SHA256:
        raise PrepareError('assessment cargo config drift')
    budget.check_deadline()
    result['toolchain']=observe_local_assessment_toolchain(toolchain)
    return result


def copy_owned_assessment_preparation(source, dest, *, context):
    """Re-snapshot selected preparation; no network or trust in reported hashes."""
    import suggestion_evidence as ev
    import suggestion_readback as reader
    source=Path(source);dest=Path(dest)
    budget=MaterializeBudget(MATERIALIZE_CEILINGS)
    with reader._directory(reader._absolute_parts(source)) as fd:
        reader._inventory(fd,('prepare.json','subject','corpus','vendor','tool'))
        raw=reader._read_file(fd,'prepare.json',remaining=65536,seen=set())
    if raw!=context.prepare_raw:ev.refuse('binding','prepare-authorization')
    snapshots={key:_assessment_tree_snapshot(source/key,budget,empty=key=='vendor')
               for key in ('subject','corpus','vendor','tool')}
    corpus_files,corpus_directories=snapshots['corpus']
    if corpus_directories!=('vectors',) or any(not name.startswith('vectors/') for name in corpus_files):
        ev.refuse('filesystem','surplus-member')
    dest.mkdir()
    for key,snapshot in snapshots.items():_write_assessment_tree(snapshot,dest/key)
    plan=ev.decode(dict(context.assessment_inputs.retained_members)['plan.json'])
    mats=_assessment_materialized(dest,variant=context.variant,plan=plan)
    prepare=ev.decode(context.prepare_raw)
    for key,value in prepare['materialized'].items():
        if mats[key]!=value:ev.refuse('binding','corpus-derivation')
    mats['toolchain']=prepare['runtime']['toolchain']
    return mats


def commit_assessment_dest(state):
    """Publish a settled execution, retaining diagnostics on publication failure.

    Same documented lease/precheck/rename exclusion and residual TOCTOU as the
    historical helper. Unlike preparation, failed execution staging is evidence.
    """
    dest=Path(state['dest']);staging=Path(state['staging'])
    if dest.exists() or dest.is_symlink():raise PrepareError('assessment dest exists')
    _fsync_tree(staging)
    os.rename(staging,dest)
    _release_owned_lease(state['lease'],state['token'])
    return dest
