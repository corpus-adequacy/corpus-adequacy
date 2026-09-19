"""Bounded external input loaders for owned assessment (#224).

No verifier CLI, package reader, evaluator dispatch or runtime entry point yet.
The caller explicitly selects the original-basis directory and expected file.
Only immutable snapshots leave this filesystem boundary; they grant no consent.
"""
from contextlib import contextmanager
import os
import stat

import suggestion_evidence as ev

MEMBER_BYTES = 65536
BASIS_TOTAL_BYTES = 393216
_VECTOR_NAMES = frozenset(p.split('/', 1)[1] for p in ev.BASIS_PATHS if p.startswith('vectors/'))


def _require_support():
    if (not all(hasattr(os, name) for name in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK'))
            or os.open not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
            or os.stat not in os.supports_follow_symlinks
            or os.scandir not in os.supports_fd):
        ev.refuse('support', 'unsupported-filesystem')


def _signature(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _stat_at(parent, name):
    return os.stat(name, dir_fd=parent, follow_symlinks=False)


def _assert_same(before, after):
    if _signature(before) != _signature(after):
        ev.refuse('filesystem', 'nonregular-member')


@contextmanager
def _child(parent, name, *, directory):
    """Open one component and detect replacement between stat and open/close."""
    before = _stat_at(parent, name)
    check = stat.S_ISDIR if directory else stat.S_ISREG
    if not check(before.st_mode) or (not directory and before.st_nlink != 1):
        ev.refuse('filesystem', 'nonregular-member')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory:
        flags |= os.O_DIRECTORY
    fd = os.open(name, flags, dir_fd=parent)
    try:
        opened = os.fstat(fd)
        if not check(opened.st_mode) or (not directory and opened.st_nlink != 1):
            ev.refuse('filesystem', 'nonregular-member')
        _assert_same(before, opened)
        yield fd
        _assert_same(opened, os.fstat(fd))
        _assert_same(opened, _stat_at(parent, name))
    finally:
        os.close(fd)


def _absolute_parts(path):
    value = os.fspath(path)
    if type(value) is not str or not value or '\x00' in value or '\\' in value:
        ev.refuse('input', 'argument-invalid')
    if '..' in value.split('/'):
        ev.refuse('filesystem', 'unsafe-member')
    # No resolve()/realpath(): following an ancestor link is not a safe-open.
    return tuple(p for p in os.path.abspath(value).split('/') if p)


@contextmanager
def _directory(parts):
    """Walk from filesystem root, keeping each open independent of later links."""
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts:
            before = _stat_at(fd, part)
            if not stat.S_ISDIR(before.st_mode):
                ev.refuse('filesystem', 'nonregular-member')
            new_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                _assert_same(before, os.fstat(new_fd))
                _assert_same(before, _stat_at(fd, part))
            except BaseException:
                os.close(new_fd)
                raise
            os.close(fd)
            fd = new_fd
        yield fd
    finally:
        os.close(fd)


def _inventory(fd, expected):
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > len(expected):
                ev.refuse('filesystem', 'surplus-member')
    if len(names) != len(set(n.casefold() for n in names)):
        ev.refuse('filesystem', 'duplicate-member')
    if set(names) != set(expected):
        ev.refuse('filesystem', 'surplus-member' if set(names) - set(expected) else 'missing-member')


def _read_file(parent, name, *, remaining, seen):
    with _child(parent, name, directory=False) as fd:
        st = os.fstat(fd)
        identity = (st.st_dev, st.st_ino)
        if identity in seen:
            ev.refuse('filesystem', 'duplicate-member')
        seen.add(identity)
        if st.st_size > MEMBER_BYTES:
            ev.refuse('limits', 'member-bytes')
        if st.st_size > remaining:
            ev.refuse('limits', 'aggregate-bytes')
        limit = min(MEMBER_BYTES, remaining)
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(16384, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                ev.refuse('limits', 'member-bytes' if limit == MEMBER_BYTES else 'aggregate-bytes')
            chunks.append(chunk)
        return b''.join(chunks)


def load_assessment_basis(path):
    """Snapshot exact original LICENSE+vectors tree and check installed oracle."""
    _require_support()
    parts = _absolute_parts(path)
    try:
        with _directory(parts) as root:
            original = os.fstat(root)
            _inventory(root, ('LICENSE', 'vectors'))
            seen = set()
            license_raw = _read_file(root, 'LICENSE', remaining=BASIS_TOTAL_BYTES, seen=seen)
            snapshot = [('LICENSE', license_raw)]
            total = len(license_raw)
            with _child(root, 'vectors', directory=True) as vectors:
                _inventory(vectors, _VECTOR_NAMES)
                for name in sorted(_VECTOR_NAMES):
                    raw = _read_file(vectors, name, remaining=BASIS_TOTAL_BYTES-total, seen=seen)
                    total += len(raw)
                    snapshot.append(('vectors/'+name, raw))
                _inventory(vectors, _VECTOR_NAMES)
            _inventory(root, ('LICENSE', 'vectors'))
            _assert_same(original, os.fstat(root))
        snapshot = tuple(sorted(snapshot))
        ev.require_basis(snapshot)
        return snapshot
    except OSError:
        ev.refuse('filesystem', 'unreadable')


def load_expected(path):
    """Read caller-selected external expected bytes; never create expectations."""
    _require_support()
    parts = _absolute_parts(path)
    if not parts:
        ev.refuse('input', 'argument-invalid')
    try:
        with _directory(parts[:-1]) as parent:
            raw = _read_file(parent, parts[-1], remaining=MEMBER_BYTES, seen=set())
        ev.require_expected(raw)
        return raw
    except OSError:
        ev.refuse('filesystem', 'unreadable')
