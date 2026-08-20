"""Bounded disposable working-tree copy for process/batch mutation.

process/batch measure in a unique temp copy of repo_root. The declared
user checkout is not written. Each materialize creates a new root with
tempfile.mkdtemp in the system temp directory; the root never lies under
repo_root. A keyed pointer file under that same temp directory names the
current unique root so an external test can find it. The pointer is not
the tree and must not live in the checkout.

Abrupt SIGKILL of the tool cannot run Python finally, so orphaned temp
bytes may remain. The next run uses a new root and may remove the previous
pointer target. Never a sandbox. Never a git worktree. Never the #4 output
ceiling. Never #11 module isolation. Never #2 HEAD-vs-dirty provenance.

`.git` is omitted. Build rules that require git metadata in the tree are
unsupported. Tool-owned scratch names (corpus-adequacy-muttree-*) are
skipped if they appear in the walk. Symlinks, FIFOs, sockets, and devices
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
_POINTER_PREFIX = "corpus-adequacy-muttree-"
_SKIP_PREFIXES = ("corpus-adequacy-muttree-",)


class IsolationError(Exception):
    """The disposable working-tree copy could not be materialized."""


def _pointer_key(repo_root: Path) -> str:
    return hashlib.sha256(str(Path(repo_root).resolve()).encode("utf-8")).hexdigest()[:16]


def isolated_tree_pointer(repo_root: Path) -> Path:
    """Stable discoverability pointer outside repo_root. Not the tree."""
    return Path(tempfile.gettempdir()) / ("%s%s.ptr" % (_POINTER_PREFIX, _pointer_key(repo_root)))


def _contained(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _safe_to_rmtree(path: Path, repo_root: Path) -> bool:
    try:
        resolved = path.resolve()
        tmp = Path(tempfile.gettempdir()).resolve()
        resolved.relative_to(tmp)
    except (OSError, ValueError):
        return False
    if _contained(resolved, Path(repo_root)):
        return False
    return True


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

        unique = Path(tempfile.mkdtemp(prefix=_POINTER_PREFIX, dir=str(sys_tmp)))
        if _contained(unique, src_resolved):
            shutil.rmtree(unique, ignore_errors=True)
            raise IsolationError("temp-root %s lies under repo_root %s" % (unique, src_resolved))
        self.root = unique
        ptr = isolated_tree_pointer(src_resolved)
        try:
            ptr.write_text(str(unique), encoding="utf-8")
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
        if not ptr.is_file():
            return
        try:
            named = Path(ptr.read_text(encoding="utf-8").strip())
        except OSError:
            return
        if not named.parts:
            return
        if _safe_to_rmtree(named, repo_root) and named.exists():
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
                    if any(name.startswith(pfx) for pfx in _SKIP_PREFIXES):
                        continue
                    copied_bytes, copied_files = self._copy_dir(
                        Path(entry.path), dest_dir / name, repo_root,
                        copied_bytes, copied_files, cap, file_cap)
                    continue
                if stat.S_ISREG(st.st_mode):
                    if copied_files + 1 > file_cap:
                        raise IsolationError(
                            "materialization exceeds the file ceiling of %d" % file_cap)
                    if copied_bytes + st.st_size > cap:
                        raise IsolationError(
                            "materialization exceeds the ceiling of %d bytes" % cap)
                    data = Path(entry.path).read_bytes()
                    if copied_bytes + len(data) > cap:
                        raise IsolationError(
                            "materialization exceeds the ceiling of %d bytes" % cap)
                    dest = dest_dir / name
                    dest.write_bytes(data)
                    os.chmod(dest, stat.S_IMODE(st.st_mode))
                    copied_files += 1
                    copied_bytes += len(data)
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
        if ptr is not None and ptr.is_file():
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
                try:
                    ptr.unlink()
                except OSError:
                    pass
        self.root = None

    def __enter__(self) -> Path:
        return self.materialize()

    def __exit__(self, *exc) -> None:
        self.cleanup()
