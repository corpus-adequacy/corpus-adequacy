#!/usr/bin/env python3
"""Checksums and safe extraction for an archived terminal hosted attempt (#188).

A terminal attempt's artifacts expire with the repository's retention setting. The owner may keep
the same bytes as assets of an immutable release: the artifact ZIPs as the Actions API served
them, the API records, the run log, and one `SHA256SUMS`. This helper only works on a local
directory holding those assets:

- `sums DIR [--write]` computes the canonical `SHA256SUMS` over the assets;
- `check DIR` requires the assets to be exactly the files `SHA256SUMS` lists, with those digests;
- `extract DIR DEST` checks, then unpacks each artifact ZIP into `DEST/<zip stem>/`, flat and
  bounded, for `contained_hosted_publication.py readback`.

It never downloads, uploads, tags, dispatches or edits a release, and it adds no claim to the
bytes it checks: a matching checksum file binds bytes to names, not to a run or an author. A set
that does not check is refused as it is; it is not repaired in place.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from pathlib import Path

SUMS_FILENAME = "SHA256SUMS"
# The release notes travel as the release body, not as an asset; a local copy may sit beside the
# assets and is neither listed nor required.
NOT_ASSETS = (SUMS_FILENAME, "NOTES.md")
MAX_ASSETS = 64
MAX_SUMS_BYTES = 65536
# One artifact's extracted bytes: the hosted lane's own 5 MiB artifact ceiling.
MAX_EXTRACTED_BYTES = 5242880
MAX_ZIP_MEMBERS = 512
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ArchiveError(Exception):
    """A named refusal. Nothing is written after one."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_dir(path: Path, where: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ArchiveError(where)
    return path


def asset_files(directory) -> dict:
    """name -> path for every asset: flat, regular, named plainly, and bounded in count."""
    root = _require_dir(Path(directory), "archive_dir")
    assets = {}
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        if entry.name in NOT_ASSETS:
            if entry.is_symlink() or not entry.is_file():
                raise ArchiveError("archive_entry:%s" % entry.name)
            continue
        if not _NAME.match(entry.name):
            raise ArchiveError("archive_name:%s" % entry.name)
        mode = entry.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise ArchiveError("archive_entry:%s" % entry.name)
        assets[entry.name] = entry
    if not assets:
        raise ArchiveError("archive_empty")
    if len(assets) > MAX_ASSETS:
        raise ArchiveError("archive_asset_count")
    return assets


def encode_sums(digests: dict) -> bytes:
    """Canonical shasum text mode, sorted by name: `<hex64>  <name>\\n`."""
    lines = []
    for name in sorted(digests):
        if not _NAME.match(name) or not _HEX64.match(digests[name]):
            raise ArchiveError("sums_entry")
        lines.append("%s  %s\n" % (digests[name], name))
    return "".join(lines).encode("ascii")


def parse_sums(raw: bytes) -> dict:
    if len(raw) > MAX_SUMS_BYTES:
        raise ArchiveError("sums_bytes")
    try:
        text = raw.decode("ascii")
    except UnicodeError as exc:
        raise ArchiveError("sums_encoding") from exc
    if not text.endswith("\n"):
        raise ArchiveError("sums_shape")
    digests = {}
    for line in text[:-1].split("\n"):
        match = re.match(r"^([0-9a-f]{64}) ([ *])(.+)$", line)
        if match is None:
            raise ArchiveError("sums_line")
        digest, mode, name = match.groups()
        if mode != " ":
            raise ArchiveError("sums_mode")
        if not _NAME.match(name) or name in NOT_ASSETS:
            raise ArchiveError("sums_name")
        if name in digests:
            raise ArchiveError("sums_duplicate")
        digests[name] = digest
    if encode_sums(digests) != raw:
        raise ArchiveError("sums_canonical")
    return digests


def compute_sums(directory) -> bytes:
    return encode_sums({name: _sha256(path) for name, path in asset_files(directory).items()})


def write_sums(directory) -> dict:
    root = Path(directory)
    target = root / SUMS_FILENAME
    if target.exists() or target.is_symlink():
        raise ArchiveError("sums_exists")
    raw = compute_sums(root)
    target.write_bytes(raw)
    return {"assets": len(parse_sums(raw)), "sha256sums_sha256": hashlib.sha256(raw).hexdigest()}


def check_archive(directory) -> dict:
    root = Path(directory)
    assets = asset_files(root)
    sums_path = root / SUMS_FILENAME
    if sums_path.is_symlink() or not sums_path.is_file():
        raise ArchiveError("sums_absent")
    if sums_path.stat().st_size > MAX_SUMS_BYTES:
        raise ArchiveError("sums_bytes")
    raw = sums_path.read_bytes()
    listed = parse_sums(raw)
    if sorted(listed) != sorted(assets):
        missing = sorted(set(listed) - set(assets))
        extra = sorted(set(assets) - set(listed))
        raise ArchiveError("archive_set:missing=%s,extra=%s" % (",".join(missing),
                                                               ",".join(extra)))
    for name, path in assets.items():
        if _sha256(path) != listed[name]:
            raise ArchiveError("archive_digest:%s" % name)
    return {"assets": len(listed), "sha256sums_sha256": hashlib.sha256(raw).hexdigest()}


def _safe_members(archive: zipfile.ZipFile, zip_name: str) -> list:
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ZIP_MEMBERS:
        raise ArchiveError("zip_member_count:%s" % zip_name)
    seen = set()
    total = 0
    for info in infos:
        name = info.filename
        if (info.is_dir() or "/" in name or "\\" in name or name in (".", "..")
                or not _NAME.match(name)):
            raise ArchiveError("zip_member_name:%s" % zip_name)
        if name in seen:
            raise ArchiveError("zip_member_duplicate:%s" % zip_name)
        seen.add(name)
        # A file-type field that names anything but a regular file (symlink, device, fifo) is
        # refused; an absent type field is how many writers record a plain file.
        file_type = stat.S_IFMT(info.external_attr >> 16)
        if file_type and file_type != stat.S_IFREG:
            raise ArchiveError("zip_member_type:%s" % zip_name)
        if info.flag_bits & 0x1:
            raise ArchiveError("zip_member_encrypted:%s" % zip_name)
        total += info.file_size
        if total > MAX_EXTRACTED_BYTES:
            raise ArchiveError("zip_extracted_bytes:%s" % zip_name)
    return infos


def extract_archive(directory, dest) -> dict:
    """Check, then unpack every `*.zip` asset into `DEST/<stem>/`; nothing else is written."""
    root = Path(directory)
    check_archive(root)
    dest = Path(dest)
    # A linked destination would carry every member to wherever it points; refuse it. Linked
    # ancestors (a system /tmp) are the reader's own choice and are not judged.
    if dest.is_symlink() or (dest.exists() and not dest.is_dir()):
        raise ArchiveError("extract_dest")
    zips = {name: path for name, path in asset_files(root).items() if name.endswith(".zip")}
    if not zips:
        raise ArchiveError("archive_no_zip")
    plans = []
    for name, path in sorted(zips.items()):
        target = dest / name[:-len(".zip")]
        if target.exists() or target.is_symlink():
            raise ArchiveError("extract_target_exists:%s" % target.name)
        try:
            with zipfile.ZipFile(path) as archive:
                infos = _safe_members(archive, name)
                if archive.testzip() is not None:
                    raise ArchiveError("zip_corrupt:%s" % name)
                members = []
                budget = MAX_EXTRACTED_BYTES
                for info in infos:
                    # The declared sizes were bounded above; the bytes actually read are
                    # bounded here too, in chunks, so the ceiling caps memory as well and does
                    # not rest on the header telling the truth or on zipfile noticing.
                    chunks = []
                    with archive.open(info) as handle:
                        while True:
                            chunk = handle.read(min(65536, budget + 1))
                            if not chunk:
                                break
                            budget -= len(chunk)
                            if budget < 0:
                                raise ArchiveError("zip_extracted_bytes:%s" % name)
                            chunks.append(chunk)
                    members.append((info.filename, b"".join(chunks)))
                plans.append((target, members))
        except zipfile.BadZipFile as exc:
            raise ArchiveError("zip_corrupt:%s" % name) from exc
    dest.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink() or not dest.is_dir():
        raise ArchiveError("extract_dest")
    written = {}
    for target, members in plans:
        target.mkdir()
        if target.is_symlink() or not target.is_dir():
            raise ArchiveError("extract_target:%s" % target.name)
        for member_name, data in members:
            # Created new, never through a link at the final component. A directory swapped
            # for a link by a concurrent writer inside DEST is outside this helper's threat
            # model: DEST is the reader's own, freshly created directory.
            flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
            fd = os.open(target / member_name, flags, 0o644)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
        written[target.name] = sorted(member_name for member_name, _ in members)
    return written


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Checksums and safe extraction for an archived terminal hosted attempt")
    sub = parser.add_subparsers(dest="command", required=True)
    sums = sub.add_parser("sums", help="Print (or --write) the canonical SHA256SUMS")
    sums.add_argument("directory")
    sums.add_argument("--write", action="store_true")
    check = sub.add_parser("check", help="Require the assets to match SHA256SUMS exactly")
    check.add_argument("directory")
    extract = sub.add_parser("extract", help="Check, then unpack every artifact ZIP")
    extract.add_argument("directory")
    extract.add_argument("dest")
    args = parser.parse_args(argv)
    try:
        if args.command == "sums":
            if args.write:
                result = write_sums(args.directory)
            else:
                sys.stdout.write(compute_sums(args.directory).decode("ascii"))
                return 0
        elif args.command == "check":
            result = check_archive(args.directory)
        else:
            result = {"extracted": extract_archive(args.directory, args.dest)}
    except (ArchiveError, OSError) as exc:
        print("archive refused: %s" % exc, file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
