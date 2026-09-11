#!/usr/bin/env python3
"""Hosted packet delivery for the contained hosted lane (#107). Stdlib only.

Phase 3 of the hosted route reads an owner-authorized packet that lives outside R's tree: the
assets of one GitHub release plus a manifest asset listing each file's SHA-256. The manifest's
own SHA-256 is the only identity input. This module fetches that packet into one fresh
directory under the checked-out workspace, and records phase 1's PREPARE bytes beside the run
identity that produced them.

Order is the contract. The destination is refused if it already exists or is tracked in the
checkout, before any network call. The manifest is downloaded under its own byte ceiling and its
digest is compared before a single byte of it is parsed. Parsing is strict: exact keys,
duplicate keys refused, a closed file-name set, and each listed name refused if it is absolute,
contains `..`, a path separator or a control character, or would leave the destination. Each
listed asset is downloaded individually (no archive is extracted) under a per-file ceiling and
held to its manifest digest. Only after every asset is verified is anything written, each file
created new and regular (never through an existing path or link). The pins are copied from the
checked-out `measurements/aee-checker-25b9dfa/`, never from the release. Nothing is written
outside the destination. Every refusal is a named `PacketError`.

Non-claims: a verified manifest digest binds bytes to the digest the operator dispatched with;
it is not authentication of the release author, and the recorded PREPARE digest proves transport
only, because the job that computed it also produced the bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath, PureWindowsPath

MANIFEST_SCHEMA = "corpus-adequacy.hosted-packet-manifest.v0"
MANIFEST_FILENAME = "hosted-packet-manifest.v0.json"
MANIFEST_KEYS = ("files", "schema")
AUTHORIZE_FILENAME = "authorize.v0.json"
BINDINGS_FILENAME = "hosted-dispatch-bindings.v0.json"
PREPARE_FILENAME = "prepare.v1.json"
# The closed file-name set. The gate reads these fixed names, so a manifest may list exactly
# these and nothing else.
PACKET_FILENAMES = (AUTHORIZE_FILENAME, BINDINGS_FILENAME, PREPARE_FILENAME)
PINS_DIRNAME = "pins"
PINS_SOURCE = ("measurements", "aee-checker-25b9dfa")
# The fixed fresh directory phase 3 fetches into. It must not exist in R's tree.
PACKET_DIRNAME = "hosted-packet"
PACKET_ENTRIES = tuple(sorted(PACKET_FILENAMES + (MANIFEST_FILENAME, PINS_DIRNAME)))
MAX_MANIFEST_BYTES = 65536
MAX_FILE_BYTES = 5242880
MAX_PIN_FILES = 16
FETCH_TIMEOUT_SECONDS = 60
GIT_TIMEOUT_SECONDS = 30
RELEASE_ASSET_URL = "https://github.com/%s/releases/download/%s/%s"
RELEASE_HOST = "github.com"
# The only host a release download may be redirected to: GitHub's hosted-runner docs list it as
# "Needed for downloading release assets". A move by GitHub refuses (fail closed) until this
# changes; it never widens to another host on its own.
REDIRECT_HOSTS = ("release-assets.githubusercontent.com",)
PREPARE_RECORD_SCHEMA = "corpus-adequacy.hosted-prepare-record.v0"
PREPARE_RECORD_FILENAME = "hosted-prepare-record.v0.json"
PREPARE_RECORD_ENV = (
    ("github_sha", "GITHUB_SHA"),
    ("github_workflow_sha", "GITHUB_WORKFLOW_SHA"),
    ("image_os", "ImageOS"),
    ("image_version", "ImageVersion"),
)
PREPARE_RECORD_NON_CLAIMS = (
    "The PREPARE digest was computed by the job that produced the bytes; it proves transport "
    "to the owner, not what ran.",
    "ImageOS and ImageVersion are the runner image's own labels, not an attestation.",
    "Not authentication, endorsement, audit or certification.",
)

_HEX = frozenset("0123456789abcdef")
_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}"
_REPOSITORY_RE = re.compile(r"%s/%s\Z" % (_SEGMENT, _SEGMENT))
_TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class PacketError(Exception):
    """Packet delivery was refused; the message names the check that refused."""


def _require_hex(value, length: int, reason: str) -> str:
    if (not isinstance(value, str) or len(value) != length
            or any(ch not in _HEX for ch in value)):
        raise PacketError(reason)
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require_repository(value) -> str:
    if not isinstance(value, str) or not _REPOSITORY_RE.match(value) or ".." in value:
        raise PacketError("repository")
    return value


def require_tag(value) -> str:
    if not isinstance(value, str) or not _TAG_RE.match(value) or ".." in value:
        raise PacketError("tag")
    return value


def require_safe_name(name) -> str:
    """One file name that stays inside the directory it is joined to, or a named refusal."""
    if type(name) is not str or not name:
        raise PacketError("manifest_name_type")
    if ".." in name:
        raise PacketError("manifest_name_dotdot")
    windows = PureWindowsPath(name)
    if PurePosixPath(name).is_absolute() or windows.is_absolute() or windows.drive:
        raise PacketError("manifest_name_absolute")
    if "/" in name or "\\" in name:
        raise PacketError("manifest_name_separator")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name):
        raise PacketError("manifest_name_control")
    anchor = os.path.normpath(os.path.join(os.sep, "destination"))
    joined = os.path.normpath(os.path.join(anchor, name))
    if os.path.dirname(joined) != anchor or os.path.basename(joined) != name:
        raise PacketError("manifest_name_escapes")
    return name


def _unique_pairs(pairs):
    keys = [key for key, _value in pairs]
    if len(set(keys)) != len(keys):
        raise PacketError("manifest_duplicate_key")
    return dict(pairs)


def parse_manifest(raw: bytes) -> dict:
    """Strictly parse manifest bytes whose digest the caller has already verified.

    Returns {file name: sha256} over exactly the closed file-name set. This is the one manifest
    rule: the fetch step and the gate both call it, so they cannot disagree on what a manifest
    lists.
    """
    try:
        text = raw.decode("utf-8")
        doc = json.loads(text, object_pairs_hook=_unique_pairs)
    except PacketError:
        raise
    except (UnicodeError, ValueError) as exc:
        raise PacketError("manifest_json") from exc
    if type(doc) is not dict or tuple(sorted(doc)) != MANIFEST_KEYS:
        raise PacketError("manifest_keys")
    if doc["schema"] != MANIFEST_SCHEMA:
        raise PacketError("manifest_schema")
    files = doc["files"]
    if type(files) is not dict:
        raise PacketError("manifest_files")
    for name, digest in files.items():
        require_safe_name(name)
        if name not in PACKET_FILENAMES:
            raise PacketError("manifest_name_unknown")
        _require_hex(digest, 64, "manifest_file_digest")
    if set(files) != set(PACKET_FILENAMES):
        raise PacketError("manifest_files_incomplete")
    return {name: files[name] for name in PACKET_FILENAMES}


def release_asset_url(repository: str, tag: str, name: str) -> str:
    return RELEASE_ASSET_URL % (
        repository, urllib.parse.quote(tag, safe=""), urllib.parse.quote(name, safe=""))


def _plain_host(parts) -> str | None:
    """The host of an https URL with no userinfo and no explicit port, else None."""
    try:
        port = parts.port
    except ValueError:
        return None
    if parts.username is not None or parts.password is not None or port is not None:
        return None
    return parts.hostname


class _PinnedRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only over HTTPS to the release-asset host GitHub documents.

    The manifest digest already binds every byte, so this does not add integrity. It bounds
    where the runner can be sent: GitHub's hosted-runner documentation names
    `release-assets.githubusercontent.com` as the host needed for downloading release assets,
    and a release download is one redirect from github.com to it.
    """

    max_redirections = 2

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme != "https":
            raise PacketError("fetch_redirect_scheme")
        if _plain_host(parts) not in REDIRECT_HOSTS:
            raise PacketError("fetch_redirect_host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def default_open_url(url: str, max_bytes: int) -> bytes:
    """Fetch one public release asset over HTTPS, reading at most max_bytes + 1 bytes."""
    if not isinstance(url, str) or urllib.parse.urlsplit(url).scheme != "https":
        raise PacketError("fetch_scheme")
    if _plain_host(urllib.parse.urlsplit(url)) != RELEASE_HOST:
        raise PacketError("fetch_host")
    opener = urllib.request.build_opener(_PinnedRedirect())
    request = urllib.request.Request(url, headers={
        "Accept": "application/octet-stream",
        "User-Agent": "corpus-adequacy-hosted-packet",
    })
    chunks = []
    total = 0
    try:
        with opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https":
                raise PacketError("fetch_redirect_scheme")
            if _plain_host(final) not in (RELEASE_HOST,) + REDIRECT_HOSTS:
                raise PacketError("fetch_redirect_host")
            if getattr(response, "status", 200) != 200:
                raise PacketError("fetch_status")
            declared = response.headers.get("Content-Length")
            if declared is not None and declared.isdigit() and int(declared) > max_bytes:
                raise PacketError("fetch_oversize")
            while True:
                chunk = response.read(min(65536, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    raise PacketError("fetch_oversize")
    except PacketError:
        raise
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise PacketError("fetch_failed") from exc
    return b"".join(chunks)


def _fetch_bounded(open_url, url: str, cap: int, oversize: str) -> bytes:
    raw = open_url(url, cap)
    if type(raw) is not bytes:
        raise PacketError("fetch_failed")
    if len(raw) > cap:
        raise PacketError(oversize)
    return raw


def _git_env() -> dict:
    # GIT_DIR/GIT_INDEX_FILE from an outer process would point the check at another repository.
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def resolve_workspace(workspace_root) -> Path:
    if workspace_root is None or (isinstance(workspace_root, str) and not workspace_root):
        raise PacketError("workspace_root")
    root = Path(workspace_root)
    try:
        st = os.lstat(root)
    except OSError:
        raise PacketError("workspace_root") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise PacketError("workspace_root")
    return Path(os.path.realpath(root))


def _tracked_under(workspace: Path, dest: str) -> bool:
    try:
        proc = subprocess.run(
            ["git", "-C", str(workspace), "ls-files", "-z", "--", dest],
            capture_output=True, timeout=GIT_TIMEOUT_SECONDS, env=_git_env(), check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PacketError("checkout_unreadable") from exc
    if proc.returncode != 0:
        raise PacketError("checkout_unreadable")
    return bool(proc.stdout)


def require_fresh_destination(workspace: Path, dest) -> Path:
    """One new directory directly under the workspace, absent on disk and in the checkout."""
    try:
        require_safe_name(dest)
    except PacketError:
        raise PacketError("destination_path") from None
    target = workspace / dest
    if os.path.lexists(target):
        raise PacketError("destination_exists")
    if _tracked_under(workspace, dest):
        raise PacketError("destination_tracked")
    return target


def _read_regular(path: Path, cap: int, *, not_regular: str, oversize: str) -> bytes:
    try:
        st = os.lstat(path)
    except OSError:
        raise PacketError(not_regular) from None
    if not stat.S_ISREG(st.st_mode):
        raise PacketError(not_regular)
    if st.st_size > cap:
        raise PacketError(oversize)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise PacketError(not_regular) from None
    with os.fdopen(fd, "rb") as handle:
        raw = handle.read(cap + 1)
    if len(raw) > cap:
        raise PacketError(oversize)
    return raw


def read_pins_source(workspace: Path) -> list:
    """R's pins, from the checked-out tree: regular files only, no link anywhere on the path."""
    current = workspace
    for part in PINS_SOURCE:
        current = current / part
        try:
            st = os.lstat(current)
        except OSError:
            raise PacketError("pins_source") from None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise PacketError("pins_source")
    names = sorted(os.listdir(current))
    if not names or len(names) > MAX_PIN_FILES:
        raise PacketError("pins_source")
    pins = []
    for name in names:
        try:
            require_safe_name(name)
        except PacketError:
            raise PacketError("pins_source_entry") from None
        pins.append((name, _read_regular(
            current / name, MAX_FILE_BYTES,
            not_regular="pins_source_entry", oversize="pins_source_entry")))
    return pins


def write_new_regular_file(path, raw: bytes) -> None:
    """Create `path` as a new regular file; never write through an existing path or link."""
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    try:
        fd = os.open(path, flags, 0o644)
    except FileExistsError:
        raise PacketError("file_exists") from None
    except OSError as exc:
        raise PacketError("file_write") from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise PacketError("file_not_regular")


def fetch_packet(*, repository, tag, manifest_sha256, workspace_root, dest,
                 open_url=None, max_file_bytes: int = MAX_FILE_BYTES,
                 max_manifest_bytes: int = MAX_MANIFEST_BYTES) -> dict:
    repository = require_repository(repository)
    tag = require_tag(tag)
    expected = _require_hex(manifest_sha256, 64, "manifest_sha256")
    workspace = resolve_workspace(workspace_root)
    require_fresh_destination(workspace, dest)
    fetch = open_url or default_open_url

    manifest_raw = _fetch_bounded(
        fetch, release_asset_url(repository, tag, MANIFEST_FILENAME),
        max_manifest_bytes, "manifest_oversize")
    if _sha256(manifest_raw) != expected:
        raise PacketError("manifest_digest")
    files = parse_manifest(manifest_raw)

    payloads = {}
    for name in PACKET_FILENAMES:
        raw = _fetch_bounded(
            fetch, release_asset_url(repository, tag, name), max_file_bytes, "file_oversize")
        if _sha256(raw) != files[name]:
            raise PacketError("file_digest")
        payloads[name] = raw
    pins = read_pins_source(workspace)

    # Nothing has been written yet. The destination is checked again because the network
    # phase is a window; creation itself is exclusive, so a directory or link that appeared in
    # that window refuses rather than being written through.
    target = require_fresh_destination(workspace, dest)
    try:
        os.mkdir(target)
    except FileExistsError:
        raise PacketError("destination_exists") from None
    write_new_regular_file(target / MANIFEST_FILENAME, manifest_raw)
    for name in PACKET_FILENAMES:
        write_new_regular_file(target / name, payloads[name])
    pins_dir = target / PINS_DIRNAME
    os.mkdir(pins_dir)
    for name, raw in pins:
        write_new_regular_file(pins_dir / name, raw)
    return {
        "destination": str(target),
        "manifest_sha256": expected,
        "files": dict(files),
        "pins": [name for name, _raw in pins],
    }


def record_prepare(prepare_path, out_path, *, environ=None) -> dict:
    """Record phase 1's PREPARE bytes beside the run identity and runner image that made them."""
    env = os.environ if environ is None else environ
    observed = {}
    for key, name in PREPARE_RECORD_ENV:
        value = env.get(name)
        if not isinstance(value, str) or not value:
            raise PacketError("record_env_absent")
        observed[key] = value
    _require_hex(observed["github_sha"], 40, "record_github_sha")
    _require_hex(observed["github_workflow_sha"], 40, "record_github_workflow_sha")
    raw = _read_regular(Path(prepare_path), MAX_FILE_BYTES,
                        not_regular="record_prepare", oversize="record_prepare")
    doc = {
        "schema": PREPARE_RECORD_SCHEMA,
        "prepare_file": PREPARE_FILENAME,
        "prepare_sha256": _sha256(raw),
        "prepare_bytes": len(raw),
        **observed,
        "non_claims": list(PREPARE_RECORD_NON_CLAIMS),
    }
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_new_regular_file(
        out, (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return doc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hosted_packet", description="Hosted packet delivery (#107)")
    sub = parser.add_subparsers(dest="command", required=True)
    fetch = sub.add_parser("fetch", help="Fetch a release packet bound by its manifest digest")
    fetch.add_argument("--repository", required=True)
    fetch.add_argument("--tag", required=True)
    fetch.add_argument("--manifest-sha256", required=True)
    fetch.add_argument("--workspace-root", required=True)
    fetch.add_argument("--dest", required=True)
    record = sub.add_parser("record-prepare", help="Record PREPARE bytes and run identity")
    record.add_argument("--prepare", required=True)
    record.add_argument("--out", required=True)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "fetch":
            result = fetch_packet(
                repository=args.repository, tag=args.tag,
                manifest_sha256=args.manifest_sha256,
                workspace_root=args.workspace_root, dest=args.dest)
            print(json.dumps({"files": result["files"],
                              "manifest_sha256": result["manifest_sha256"],
                              "pins": result["pins"]}, sort_keys=True))
        else:
            record_prepare(args.prepare, args.out)
    except PacketError as exc:
        print("hosted packet refused: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
