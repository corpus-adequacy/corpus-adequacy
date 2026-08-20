"""Bounded disposable working-tree copy for process/batch mutation.

process/batch measure in a unique temp copy of repo_root. The declared
user checkout is not written. Each materialize creates a new root with
tempfile.mkdtemp in the system temp directory; the root never lies under
repo_root. A keyed pointer file under that same temp directory names the
current unique root so an external test can find it. The pointer is
written atomically without following a symlink. Only a target that is a
direct child of system temp and carries the repo-keyed muttree prefix
is accepted for removal. The pointer is not the tree and must not live
in the checkout.

Abrupt SIGKILL of the tool cannot run Python finally, so orphaned temp
bytes may remain. The next run uses a new root and may remove the previous
pointer target. Never a sandbox. Never a git worktree. Never the #4 output
ceiling. Never #11 module isolation. Never #2 HEAD-vs-dirty provenance.

`.git` is omitted. Build rules that require git metadata in the tree are
unsupported. Symlinks, FIFOs, sockets, and devices
are refused fail-closed. Materialization trips file and byte ceilings
during the walk. Executable mode bits are preserved; timestamps and
ownership are not semantic input.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from pathlib import Path

MATERIALIZATION_CAP_BYTES = 64 * 1024 * 1024
MATERIALIZATION_CAP_FILES = 10_000
COPY_CHUNK_BYTES = 64 * 1024
_POINTER_PREFIX = "corpus-adequacy-muttree-"


class IsolationError(Exception):
    """The disposable working-tree copy could not be materialized."""


def _pointer_key(repo_root: Path) -> str:
    return hashlib.sha256(str(Path(repo_root).resolve()).encode("utf-8")).hexdigest()[:16]


def isolated_tree_pointer(repo_root: Path) -> Path:
    """Stable discoverability pointer outside repo_root. Not the tree."""
    return Path(tempfile.gettempdir()) / ("%s%s.ptr" % (_POINTER_PREFIX, _pointer_key(repo_root)))


def _tree_prefix(repo_root: Path) -> str:
    return "%s%s" % (_POINTER_PREFIX, _pointer_key(repo_root))


def _contained(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _safe_to_rmtree(path: Path, repo_root: Path) -> bool:
    """Only a direct system-temp child with the repo-keyed muttree prefix."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return False
    try:
        parent = path.parent.resolve()
        tmp = Path(tempfile.gettempdir()).resolve()
    except OSError:
        return False
    if parent != tmp:
        return False
    if not path.name.startswith(_tree_prefix(repo_root)):
        return False
    if _contained(path, Path(repo_root)):
        return False
    return True


def _lstat_or_none(path: Path):
    try:
        return os.lstat(path)
    except OSError:
        return None


def _unlink_pointer_inode(path: Path) -> None:
    """Remove the pointer path itself. Never follows a symlink."""
    try:
        os.unlink(path)
    except OSError:
        pass


def _write_pointer_atomic(path: Path, text: str) -> None:
    """Replace the pointer without following an existing symlink."""
    st = _lstat_or_none(path)
    if st is not None and not stat.S_ISREG(st.st_mode):
        _unlink_pointer_inode(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _copy_regular_bounded(
    src: Path,
    dest: Path,
    already: int,
    cap: int,
    *,
    chunk: int | None = None,
) -> int:
    """Copy one regular file in chunks. Memory is one small read, not the file.

    Rechecks the type on the open fd. Stops before already+written exceeds
    *cap*; the next read is at most one chunk (or remaining+1 to detect overflow).
    """
    if chunk is None:
        chunk = COPY_CHUNK_BYTES
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise IsolationError("no O_NOFOLLOW; refusing to copy %s" % src)
    fd = os.open(src, os.O_RDONLY | nofollow)
    written = 0
    out_fd = None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise IsolationError("not a regular file after open: %s" % src)
        dest.parent.mkdir(parents=True, exist_ok=True)
        out_fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        while True:
            used = already + written
            if used > cap:
                raise IsolationError("materialization exceeds the ceiling of %d bytes" % cap)
            room = cap - used
            buf = os.read(fd, min(chunk, room + 1))
            if not buf:
                break
            if used + len(buf) > cap:
                raise IsolationError("materialization exceeds the ceiling of %d bytes" % cap)
            os.write(out_fd, buf)
            written += len(buf)
        os.chmod(dest, stat.S_IMODE(st.st_mode))
        return written
    except Exception:
        if dest.exists():
            try:
                dest.unlink()
            except OSError:
                pass
        raise
    finally:
        if out_fd is not None:
            os.close(out_fd)
        os.close(fd)


class IsolatedMutationTree:
    """One owner for a unique-per-run working-tree copy and its cleanup."""

    def __init__(self, repo_root: Path | None = None) -> None:
        self.original_root = Path(repo_root) if repo_root is not None else None
        self.root: Path | None = None

    @property
    def pointer(self) -> Path | None:
        if self.original_root is None:
            return None
        return isolated_tree_pointer(self.original_root)

    def materialize(
        self,
        repo_root: Path | None = None,
        *,
        cap: int | None = None,
        file_cap: int | None = None,
    ) -> Path:
        if repo_root is not None:
            self.original_root = Path(repo_root)
        if self.original_root is None:
            raise IsolationError("original root is missing")
        if cap is None:
            cap = MATERIALIZATION_CAP_BYTES
        if file_cap is None:
            file_cap = MATERIALIZATION_CAP_FILES
        src_root = self.original_root
        try:
            src_resolved = src_root.resolve()
        except OSError as exc:
            raise IsolationError("original root is missing: %s" % src_root) from exc
        if not src_resolved.is_dir():
            raise IsolationError("original root is missing: %s" % src_root)

        sys_tmp = Path(tempfile.gettempdir()).resolve()
        if _contained(sys_tmp, src_resolved) or sys_tmp == src_resolved:
            raise IsolationError(
                "system temp dir %s lies under repo_root %s, so a copy "
                "would nest inside itself" % (sys_tmp, src_resolved))

        self._forget_previous_root(src_resolved)

        unique = Path(tempfile.mkdtemp(prefix=_tree_prefix(src_resolved), dir=str(sys_tmp)))
        if _contained(unique, src_resolved):
            shutil.rmtree(unique, ignore_errors=True)
            raise IsolationError("temp-root %s lies under repo_root %s" % (unique, src_resolved))
        self.root = unique
        ptr = isolated_tree_pointer(src_resolved)
        try:
            _write_pointer_atomic(ptr, str(unique))
            copied_bytes = 0
            copied_files = 0
            self._copy_dir(src_resolved, unique, src_resolved, copied_bytes, copied_files, cap, file_cap)
        except IsolationError:
            self.cleanup()
            raise
        except OSError as exc:
            self.cleanup()
            raise IsolationError("could not materialize isolated tree: %s" % exc) from exc
        return unique

    def _forget_previous_root(self, repo_root: Path) -> None:
        ptr = isolated_tree_pointer(repo_root)
        st = _lstat_or_none(ptr)
        if st is None:
            return
        if not stat.S_ISREG(st.st_mode):
            _unlink_pointer_inode(ptr)
            return
        try:
            named = Path(ptr.read_text(encoding="utf-8").strip())
        except OSError:
            return
        if not named.parts:
            return
        if _safe_to_rmtree(named, repo_root):
            shutil.rmtree(named, ignore_errors=True)

    def _copy_dir(
        self,
        src_dir: Path,
        dest_dir: Path,
        repo_root: Path,
        copied_bytes: int,
        copied_files: int,
        cap: int,
        file_cap: int,
    ) -> tuple[int, int]:
        dest_dir.mkdir(parents=True, exist_ok=True)
        try:
            entries = os.scandir(src_dir)
        except FileNotFoundError as exc:
            raise IsolationError("missing path during materialize: %s" % src_dir) from exc
        with entries:
            for entry in entries:
                name = entry.name
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise IsolationError("could not lstat %s: %s" % (entry.path, exc)) from exc
                if stat.S_ISLNK(st.st_mode):
                    raise IsolationError("symlink refused: %s" % entry.path)
                if stat.S_ISDIR(st.st_mode):
                    if name == ".git":
                        continue
                    copied_bytes, copied_files = self._copy_dir(
                        Path(entry.path), dest_dir / name, repo_root,
                        copied_bytes, copied_files, cap, file_cap)
                    continue
                if stat.S_ISREG(st.st_mode):
                    if copied_files + 1 > file_cap:
                        raise IsolationError(
                            "materialization exceeds the file ceiling of %d" % file_cap)
                    dest = dest_dir / name
                    n = _copy_regular_bounded(
                        Path(entry.path), dest, copied_bytes, cap)
                    copied_files += 1
                    copied_bytes += n
                    continue
                if stat.S_ISFIFO(st.st_mode):
                    kind = "fifo"
                elif stat.S_ISSOCK(st.st_mode):
                    kind = "socket"
                else:
                    kind = "device"
                raise IsolationError("refusing %s: %s" % (kind, entry.path))
        return copied_bytes, copied_files

    def cleanup(self) -> None:
        root = self.root
        ptr = self.pointer
        if root is not None:
            path = Path(root)
            if path.exists() and (self.original_root is None or _safe_to_rmtree(path, self.original_root)):
                shutil.rmtree(path, ignore_errors=True)
            elif path.exists() and self.original_root is None:
                shutil.rmtree(path, ignore_errors=True)
        if ptr is not None:
            st = _lstat_or_none(ptr)
            if st is None:
                pass
            elif not stat.S_ISREG(st.st_mode):
                _unlink_pointer_inode(ptr)
            else:
                try:
                    named = Path(ptr.read_text(encoding="utf-8").strip())
                except OSError:
                    named = None
                drop = False
                if named is None or not str(named).strip():
                    drop = True
                elif root is not None:
                    try:
                        drop = named.resolve() == Path(root).resolve() or not named.exists()
                    except OSError:
                        drop = True
                else:
                    drop = True
                if drop:
                    _unlink_pointer_inode(ptr)
        self.root = None

    def __enter__(self) -> Path:
        return self.materialize()

    def __exit__(self, *exc) -> None:
        self.cleanup()
